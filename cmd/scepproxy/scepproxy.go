package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/micromdm/scep/v2/csrverifier"
	executablecsrverifier "github.com/micromdm/scep/v2/csrverifier/executable"
	scepdepot "github.com/micromdm/scep/v2/depot"
	"github.com/micromdm/scep/v2/depot/file"
	scepproxy "github.com/micromdm/scep/v2/proxy_signer"
	scepserver "github.com/micromdm/scep/v2/server"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// version info
var (
	version = "unknown"
)

func main() {
	var caCMD = flag.NewFlagSet("ca", flag.ExitOnError)
	{
		if len(os.Args) >= 2 {
			if os.Args[1] == "ca" {
				status := caMain(caCMD)
				os.Exit(status)
			}
		}
	}

	//main flags
	var (
		flVersion            = flag.Bool("version", false, "prints version information")
		flEndpoint           = flag.String("scep-endpoint", envString("SCEP_ENDPOINT", "/scep"), "SCEP endpoint,  default to /scep")
		flHTTPAddr           = flag.String("http-addr", envString("SCEP_HTTP_ADDR", ""), "http listen address. defaults to \":8080\"")
		flPort               = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "http port to listen on (if you want to specify an address, use -http-addr instead)")
		flDepotPath          = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
		flCAPass             = flag.String("capass", envString("SCEP_CA_PASS", ""), "passwd for the ca.key")
		flChallengePassword  = flag.String("challenge", envString("SCEP_CHALLENGE_PASSWORD", ""), "enforce a challenge password")
		flCSRVerifierExec    = flag.String("csrverifierexec", envString("SCEP_CSR_VERIFIER_EXEC", ""), "will be passed the CSRs for verification")
		flDebug              = flag.Bool("debug", envBool("SCEP_LOG_DEBUG"), "enable debug logging")
		flLogJSON            = flag.Bool("log-json", envBool("SCEP_LOG_JSON"), "output JSON logs")
		flProxyUrl           = flag.String("proxy-url", envString("SCEP_PROXY_URL", ""), "URL to proxy requests to")
		flProxyCaFingerprint = flag.String("proxy-fingerprint", envString("SCEP_PROXY_FINGERPRINT", ""), "Fingerprint of the CA to proxy requests to")
		flProxyKeyBits       = flag.Int("proxy-key-length", 2048, "Key Lenght to use for proxy communication")
	)
	flag.Usage = func() {
		flag.PrintDefaults()

		fmt.Println("usage: scep [<command>] [<args>]")
		fmt.Println(" ca <args> create/manage a CA")
		fmt.Println("type <command> --help to see usage for each subcommand")
	}
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// -http-addr and -port conflict. Don't allow the user to set both.
	httpAddrSet := setByUser("http-addr", "SCEP_HTTP_ADDR")
	portSet := setByUser("port", "SCEP_HTTP_LISTEN_PORT")
	var httpAddr string
	if httpAddrSet && portSet {
		fmt.Fprintln(os.Stderr, "cannot set both -http-addr and -port")
		os.Exit(1)
	} else if httpAddrSet {
		httpAddr = *flHTTPAddr
	} else {
		httpAddr = ":" + *flPort
	}

	var logger log.Logger
	{
		if *flLogJSON {
			logger = log.NewJSONLogger(os.Stderr)
		} else {
			logger = log.NewLogfmtLogger(os.Stderr)
		}
		if !*flDebug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	lginfo := level.Info(logger)

	var err error
	var depot scepdepot.Depot // cert storage
	{
		depot, err = file.NewFileDepot(*flDepotPath)
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
	}

	var csrVerifier csrverifier.CSRVerifier
	if *flCSRVerifierExec > "" {
		executableCSRVerifier, err := executablecsrverifier.New(*flCSRVerifierExec, lginfo)
		if err != nil {
			lginfo.Log("err", err, "msg", "Could not instantiate CSR verifier")
			os.Exit(1)
		}
		csrVerifier = executableCSRVerifier
	}

	var scepEndpoint string
	if *flEndpoint == "" {
		// Set default to /scep if empty
		scepEndpoint = "/scep"
	} else {
		// Parse
		url, err := url.Parse(*flEndpoint)
		if err != nil {
			lginfo.Log("err", err, "msg", "Invalid Path", "path", *flEndpoint)
			os.Exit(1)
		}
		// Retrieve the path
		scepEndpoint = url.Path

		// Check if first char is /, if missing add it
		if scepEndpoint[0:1] != "/" {
			scepEndpoint = "/" + scepEndpoint
		}
	}

	fmt.Println(scepEndpoint)

	// Set Proxy URL
	if *flProxyUrl == "" {
		fmt.Fprintln(os.Stderr, "Proxy Url is required")
		os.Exit(1)
	}

	// Set Proxy CA Fingerprint
	if *flProxyCaFingerprint == "" {
		fmt.Fprintln(os.Stderr, "Proxy CA Fingerprint is required")
		os.Exit(1)
	}

	var svc scepserver.Service // scep service
	{
		crts, key, err := depot.CA([]byte(*flCAPass))
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
		if len(crts) < 1 {
			lginfo.Log("err", "missing CA certificate")
			os.Exit(1)
		}
		signerOpts := []scepproxy.Option{
			scepproxy.WithDebug(*flDebug),
		}

		var signer scepserver.CSRSigner = scepproxy.NewSigner(*flProxyUrl, *flProxyCaFingerprint, *flProxyKeyBits, signerOpts...)
		if *flChallengePassword != "" {
			signer = scepserver.ChallengeMiddleware(*flChallengePassword, signer)
		}
		if csrVerifier != nil {
			signer = csrverifier.Middleware(csrVerifier, signer)
		}
		svc, err = scepserver.NewService(crts[0], key, signer, scepserver.WithLogger(logger))
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
		svc = scepserver.NewLoggingService(log.With(lginfo, "component", "scep_service"), svc)
	}

	var h http.Handler // http handler
	{
		e := scepserver.MakeServerEndpoints(svc)
		e.GetEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
		e.PostEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
		h = scepserver.MakeHTTPHandler(e, svc, scepEndpoint, log.With(lginfo, "component", "http"))
	}

	// start http server
	errs := make(chan error, 2)
	go func() {
		lginfo.Log("transport", "http", "address", httpAddr, "path", scepEndpoint, "msg", "listening")
		errs <- http.ListenAndServe(httpAddr, h)
	}()
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	lginfo.Log("terminated", <-errs)
}

func caMain(cmd *flag.FlagSet) int {
	var (
		flDepotPath  = cmd.String("depot", "depot", "path to ca folder")
		flInit       = cmd.Bool("init", false, "create a new CA")
		flYears      = cmd.Int("years", 10, "default CA years")
		flKeySize    = cmd.Int("keySize", 4096, "rsa key size")
		flCommonName = cmd.String("common_name", "MICROMDM SCEP CA", "common name (CN) for CA cert")
		flOrg        = cmd.String("organization", "scep-ca", "organization for CA cert")
		flOrgUnit    = cmd.String("organizational_unit", "SCEP CA", "organizational unit (OU) for CA cert")
		flPassword   = cmd.String("key-password", "", "password to store rsa key")
		flCountry    = cmd.String("country", "US", "country for CA cert")
	)
	cmd.Parse(os.Args[2:])
	if *flInit {
		fmt.Println("Initializing new CA")
		key, err := createKey(*flKeySize, []byte(*flPassword), *flDepotPath)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		if err := createCertificateAuthority(key, *flYears, *flCommonName, *flOrg, *flOrgUnit, *flCountry, *flDepotPath); err != nil {
			fmt.Println(err)
			return 1
		}
	}

	return 0
}

// create a key, save it to depot and return it for further usage.
func createKey(bits int, password []byte, depot string) (*rsa.PrivateKey, error) {
	// create depot folder if missing
	if err := os.MkdirAll(depot, 0755); err != nil {
		return nil, err
	}
	name := filepath.Join(depot, "ca.key")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// create RSA key and save as PEM file
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	privPEMBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		rsaPrivateKeyPEMBlockType,
		x509.MarshalPKCS1PrivateKey(key),
		password,
		x509.PEMCipher3DES,
	)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(file, privPEMBlock); err != nil {
		os.Remove(name)
		return nil, err
	}

	return key, nil
}

func createCertificateAuthority(key *rsa.PrivateKey, years int, commonName string, organization string, organizationalUnit string, country string, depot string) error {
	cert := scepdepot.NewCACert(
		scepdepot.WithYears(years),
		scepdepot.WithCommonName(commonName),
		scepdepot.WithOrganization(organization),
		scepdepot.WithOrganizationalUnit(organizationalUnit),
		scepdepot.WithCountry(country),
	)
	crtBytes, err := cert.SelfSign(rand.Reader, &key.PublicKey, key)
	if err != nil {
		return err
	}

	name := filepath.Join(depot, "ca.pem")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(crtBytes)); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	return nil
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func envBool(key string) bool {
	if env := os.Getenv(key); env == "true" {
		return true
	}
	return false
}

func setByUser(flagName, envName string) bool {
	userDefinedFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		userDefinedFlags[f.Name] = true
	})
	flagSet := userDefinedFlags[flagName]
	_, envSet := os.LookupEnv(envName)
	return flagSet || envSet
}
