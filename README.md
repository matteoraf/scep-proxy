# scep-proxy
This fork adds proxy (SCEP to SCEP) functionality to the existing micromdm/scep
You can refer to the original documentation for everything, here you'll only find additional details for the proxy implementation.


## Example setup
Minimal example for proxy.

```
# PROXY:
# create a new CA
./scepserver-linux-amd64 ca -init
# start server
./scepproxy-linux-amd64 -depot depot -challenge=secret1234 -proxy-url="http://my_scep_ca/ca" -proxy-fingerprint="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" -proxy-key-length=2048

```

## Proxy Usage

The default flags configure and run the scep proxy.

`-depot` must be the path to a folder with `ca.pem` and `ca.key` files.  If you don't already have a CA to use, you can create one using the `ca` subcommand.

The scepproxy provides one HTTP endpoint, `/scep`, that facilitates the normal PKIOperation/Message parameters.

Server usage:
```sh
$ ./scepproxy-linux-amd64 -help
  -proxy-url string
    	URL to proxy requests to
  -proxy-fingerprint string
    	Fingerprint of the CA to proxy requests to
  -proxy-key-length int
    	Key Lenght to use for proxy communication (default 2048)
  -challenge string
    	enforce a challenge password (same will be used for the proxied CA)
  -csrverifierexec string
    	will be passed the CSRs for verification
  -debug
    	enable debug logging
  -depot string
    	path to ca folder (default "depot")
  -log-json
    	output JSON logs
  -port string
    	port to listen on (default "8080")
  -version
    	prints version information

```