package scepserver

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
)

// This file must contains CIDRs to check, one per line
var ipFilePath string

// This is the Header key where to look for the Origin Ip
var headerKey string

// Setter func for ipFilePath
func SetIpFilePath(path string) {
	ipFilePath = path
}

// Setter func for headerKey
func SetHeaderKey(key string) {
	headerKey = key
}

// Returns the address to use for logging purposes
func decodeRemoteAddr(r *http.Request) (remoteAddr string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ipFilePath != "" && headerKey != "" {
		isCf := checkIfProxied(host)
		if isCf {
			host = unProxy(host, r.Header)
		}
	}
	return host
}

// Check if the provided addr belongs to any of the nets in the file
func checkIfProxied(addr string) (isCf bool) {
	// Read CF IPs list from file
	cfCidrs, err := readLines(ipFilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading file with proxy CIDRs, skipping headers check. Err: ", err)
		return false
	}
	// Let's parse the IP Address that we have to check
	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		fmt.Fprintln(os.Stderr, "Error parsing IP addr, skipping headers check. IP: ", addr)
		return false
	}
	// Iterate and check if ip is in one of the subnets
	for _, cFcidr := range cfCidrs {
		// Parse the Cloudflare Network
		_, cfNet, err := net.ParseCIDR(cFcidr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing proxy CIDR, skipping headers check. Err: ", err)
			return false
		}
		if cfNet.Contains(ipAddr) {
			return true
		}
	}
	fmt.Fprintln(os.Stderr, "This IP does not belong to any of the CIDRs provided. ", addr)
	return false
}

// Check if an IP exists within the header with the provided key and returns it
func unProxy(r string, h http.Header) (proxiedIp string) {
	proxiedAddr := h.Get(headerKey)
	if proxiedAddr == "" {
		fmt.Fprintln(os.Stderr, "No Header value for key ", headerKey)
		return r
	}
	isValid := net.ParseIP(proxiedAddr)
	if isValid == nil {
		fmt.Fprintln(os.Stderr, "The header value is not a valid IP: ", proxiedAddr)
		return r
	}
	return proxiedAddr
}

// Got this from here
// https://stackoverflow.com/questions/5884154/read-text-file-into-string-array-and-write
func readLines(path string) (ipList []string, err error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to open file at ", path)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
