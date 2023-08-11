package proxy_signer

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/scep"
	"github.com/pkg/errors"
)

const fingerprintHashType = crypto.SHA256

// Signer signs x509 certificates and stores them in a Depot
type Signer struct {
	serverUrl     string
	caFingerprint string
	keyBits       int
	debug         bool
}

// Option customizes Signer
type Option func(*Signer)

// NewSigner creates a new Signer
func NewSigner(serverUrl string, caFingerprint string, keybits int, opts ...Option) *Signer {
	s := &Signer{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithDebug(debug bool) Option {
	return func(s *Signer) {
		s.debug = debug
	}
}

// SignCSR signs a certificate using Signer's Depot CA
func (s *Signer) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	ctx := context.Background()
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		stdlog.SetOutput(log.NewStdlibAdapter(logger))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		if !s.debug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
	}
	lginfo := level.Info(logger)

	// Instantiate new client
	client, err := scepclient.New(s.serverUrl, logger)
	if err != nil {
		return nil, err
	}

	// Make the private key used to sign PKI envelope
	key, err := newRSAKey(s.keyBits)
	if err != nil {
		return nil, err
	}

	// Get CSR passed from the server
	var csr *x509.CertificateRequest = m.CSR

	// Create a self-signed client certificate
	// This client cert will be used to encrypt communication with the SCEP CA server
	var signerCert *x509.Certificate
	signerCert, err = selfSign(key, csr)
	if err != nil {
		return nil, err
	}

	hash, err := validateFingerprint(s.caFingerprint)
	if err != nil {
		return nil, err
	}
	caCertsSelector := scep.FingerprintCertsSelector(fingerprintHashType, hash)

	// Let's start the communication with the signing SCEP CA
	// First we get and parse the CA Certificate(s)
	resp, certNum, err := client.GetCACert(ctx, "")
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	{
		if certNum > 1 {
			certs, err = scep.CACerts(resp)
			if err != nil {
				return nil, err
			}
		} else {
			certs, err = x509.ParseCertificates(resp)
			if err != nil {
				return nil, err
			}
		}
	}

	if s.debug {
		logCerts(level.Debug(logger), certs)
	}

	// Need to understand if and how to handle RenewalReq
	// This would require the RA to sign the envelope using the
	// existing client key, which is of course not possibile
	/*
		var msgType scep.MessageType
		{
			// TODO validate CA and set UpdateReq if needed
			if cert != nil {
				msgType = scep.RenewalReq
			} else {
				msgType = scep.PKCSReq
			}
		}
	*/

	// We set the message type as a new certificate request
	var msgType scep.MessageType = scep.PKCSReq

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  certs,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	// Forward challenge password
	tmpl.CSRReqMessage = &scep.CSRReqMessage{
		ChallengePassword: m.ChallengePassword,
	}

	msg, err := scep.NewCSRRequest(csr, tmpl, scep.WithLogger(logger), scep.WithCertsSelector(caCertsSelector))
	if err != nil {
		return nil, errors.Wrap(err, "creating csr pkiMessage")
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return nil, errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(logger), scep.WithCACerts(msg.Recipients))
		if err != nil {
			return nil, errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return nil, errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			lginfo.Log("pkiStatus", "PENDING", "msg", "sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		lginfo.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
		break // on scep.SUCCESS
	}

	if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
		return nil, errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	}

	respCert := respMsg.CertRepMessage.Certificate

	// We want to pass back the signed certificate
	return respCert, nil
}

// logCerts logs the count, number, RDN, and fingerprint of certs to logger
func logCerts(logger log.Logger, certs []*x509.Certificate) {
	logger.Log("msg", "cacertlist", "count", len(certs))
	for i, cert := range certs {
		h := fingerprintHashType.New()
		h.Write(cert.Raw)
		logger.Log(
			"msg", "cacertlist",
			"number", i,
			"rdn", cert.Subject.ToRDNSequence().String(),
			"hash_type", fingerprintHashType.String(),
			"hash", fmt.Sprintf("%x", h.Sum(nil)),
		)
	}
}

// validateFingerprint makes sure fingerprint looks like a hash.
// We remove spaces and colons from fingerprint as it may come in various forms:
//
//	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//	E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
//	e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
//	e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55
func validateFingerprint(fingerprint string) (hash []byte, err error) {
	fingerprint = strings.NewReplacer(" ", "", ":", "").Replace(fingerprint)
	hash, err = hex.DecodeString(fingerprint)
	if err != nil {
		return
	}
	if len(hash) != fingerprintHashType.Size() {
		err = fmt.Errorf("invalid %s hash length", fingerprintHashType)
	}
	return
}
