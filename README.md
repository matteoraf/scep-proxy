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
./scepproxy-linux-amd64 -scep-endpoint=myCustomEndpoint -depot depot -challenge=secret1234 -proxy-url="http://my_scep_ca/ca" -proxy-fingerprint="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" -proxy-key-length=2048

```

## Proxy Usage

The default flags configure and run the scep proxy.

`-depot` must be the path to a folder with `ca.pem` and `ca.key` files.  If you don't already have a CA to use, you can create one using the `ca` subcommand.

The scepproxy provides an HTTP endpoint which you can select by using the `-scep-endpoint` flag, it defaults to `/scep`.


## A proxy behind a proxy
If you run behind an external L7 proxy (eg. Cloduflare) which sends you the origin IP in an header, you can provide a list of IPs belonging to your proxy and the key of the header where the origin IP will be sent.
This enables logging with the correct IP, so that tools like fail2ban can do their job.
Both `ext-proxy-ip-file` and `ext-proxy-header` flags must be provided in that case.
The file must contain nets in CIDR notation (eg. 1.2.3.4/20), one per each line.

Eg. to get the Cloudflare IPs in a file:
```
wget -O /etc/scepproxy/cloudflareips https://www.cloudflare.com/ips-v4 && echo "" >> /etc/scepproxy/cloudflareips &&  wget -O - https://www.cloudflare.com/ips-v6 >> /etc/scepproxy/cloudflareips
```

Server usage:
```sh
$ ./scepproxy-linux-amd64 -help
  -scep-endpoint
      SCEP endpoint,  default to /scep
  -proxy-url string
    	URL to proxy requests to
  -proxy-fingerprint string
    	Fingerprint of the CA to proxy requests to
  -proxy-key-length int
    	Key Lenght to use for proxy communication (default 2048)
  -ext-proxy-ip-file
      Path to the file containing the CIDRs (one per line) of your external proxy (eg. Cloudflare)
  -ext-proxy-header
      The header key containing the origin IP (for Cloudflare is CF-Connecting-IP)
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

## Logging
I implemented some additional logging, in order to have the remoteAddr logged togheter with the already provided information.
My goal is to use this with a custom fail2ban filter in order to block hosts sending unauthorized requests.