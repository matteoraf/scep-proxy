package scepserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	kitlog "github.com/go-kit/kit/log"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/groob/finalizer/logutil"
	"github.com/pkg/errors"
)

type contextKey string

var contextKeyHost = contextKey("host")

// Add remoteAddr to http.Request context
func UseRequestAddr(next http.Handler) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := decodeRemoteAddr(r)
		ctx := context.Background()
		ctx = context.WithValue(ctx, contextKeyHost, remoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return fn
}

// Getter func for remoteAddr
func GetRemoteAddr(ctx context.Context) string {
	remoteAddr, ok := ctx.Value(contextKeyHost).(string)
	if !ok {
		return ""
	}
	return remoteAddr
}

func MakeHTTPHandler(e *Endpoints, svc Service, path string, logger kitlog.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorLogger(logger),
		kithttp.ServerFinalizer(logutil.NewHTTPLogger(logger).LoggingFinalizer),
	}

	getHandler := kithttp.NewServer(
		e.GetEndpoint,
		decodeSCEPRequest,
		encodeSCEPResponse,
		opts...,
	)

	postHandler := kithttp.NewServer(
		e.PostEndpoint,
		decodeSCEPRequest,
		encodeSCEPResponse,
		opts...,
	)

	// This handles non-existing routes and just returns 403 and logs the request with the host address
	nonExistingHandler := kithttp.NewServer(
		func(ctx context.Context, request interface{}) (response interface{}, err error) {
			return struct{}{}, nil
		},
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			logger.Log("filter", "fail2ban", "host", GetRemoteAddr(ctx))
			return struct{}{}, nil
		},
		func(ctx context.Context, w http.ResponseWriter, e interface{}) error {
			http.Error(w, "", http.StatusForbidden)
			return nil
		},
		opts...)

	r := mux.NewRouter()
	r.Methods("GET").Path(path).Handler(UseRequestAddr(getHandler))
	r.Methods("POST").Path(path).Handler(UseRequestAddr(postHandler))
	r.PathPrefix("/").Handler(UseRequestAddr(nonExistingHandler))
	r.PathPrefix(path).Handler(UseRequestAddr(nonExistingHandler))

	return r
}

// EncodeSCEPRequest encodes a SCEP HTTP Request. Used by the client.
func EncodeSCEPRequest(ctx context.Context, r *http.Request, request interface{}) error {
	req := request.(SCEPRequest)
	params := r.URL.Query()
	params.Set("operation", req.Operation)
	switch r.Method {
	case "GET":
		if len(req.Message) > 0 {
			var msg string
			if req.Operation == "PKIOperation" {
				msg = base64.URLEncoding.EncodeToString(req.Message)
			} else {
				msg = string(req.Message)
			}
			params.Set("message", msg)
		}
		r.URL.RawQuery = params.Encode()
		return nil
	case "POST":
		body := bytes.NewReader(req.Message)
		// recreate the request here because IIS does not support chunked encoding by default
		// and Go doesn't appear to set Content-Length if we use an io.ReadCloser
		u := r.URL
		u.RawQuery = params.Encode()
		rr, err := http.NewRequest("POST", u.String(), body)
		rr.Header.Set("Content-Type", "application/octet-stream")
		if err != nil {
			return errors.Wrapf(err, "creating new POST request for %s", req.Operation)
		}
		*r = *rr
		return nil
	default:
		return fmt.Errorf("scep: %s method not supported", r.Method)
	}
}

const maxPayloadSize = 2 << 20

func decodeSCEPRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	msg, err := message(r)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	request := SCEPRequest{
		Message:   msg,
		Operation: r.URL.Query().Get("operation"),
	}

	return request, nil
}

// extract message from request
func message(r *http.Request) ([]byte, error) {
	switch r.Method {
	case "GET":
		var msg string
		q := r.URL.Query()
		if _, ok := q["message"]; ok {
			msg = q.Get("message")
		}
		op := q.Get("operation")
		if op == "PKIOperation" {
			msg2, err := url.PathUnescape(msg)
			if err != nil {
				return nil, err
			}
			return base64.StdEncoding.DecodeString(msg2)
		}
		return []byte(msg), nil
	case "POST":
		return ioutil.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	default:
		return nil, errors.New("method not supported")
	}
}

// EncodeSCEPResponse writes a SCEP response back to the SCEP client.
func encodeSCEPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(SCEPResponse)
	if resp.Err != nil {
		http.Error(w, resp.Err.Error(), http.StatusInternalServerError)
		return nil
	}
	w.Header().Set("Content-Type", contentHeader(resp.operation, resp.CACertNum))
	w.Write(resp.Data)
	return nil
}

// DecodeSCEPResponse decodes a SCEP response
func DecodeSCEPResponse(ctx context.Context, r *http.Response) (interface{}, error) {
	if r.StatusCode != http.StatusOK && r.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 4096))
		return nil, fmt.Errorf("http request failed with status %s, msg: %s",
			r.Status,
			string(body),
		)
	}
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	resp := SCEPResponse{
		Data: data,
	}
	header := r.Header.Get("Content-Type")
	if header == certChainHeader {
		// we only set it to two to indicate a cert chain.
		// the actual number of certs will be in the payload.
		resp.CACertNum = 2
	}
	return resp, nil
}

const (
	certChainHeader = "application/x-x509-ca-ra-cert"
	leafHeader      = "application/x-x509-ca-cert"
	pkiOpHeader     = "application/x-pki-message"
)

func contentHeader(op string, certNum int) string {
	switch op {
	case "GetCACert":
		if certNum > 1 {
			return certChainHeader
		}
		return leafHeader
	case "PKIOperation":
		return pkiOpHeader
	default:
		return "text/plain"
	}
}
