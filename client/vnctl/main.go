// vnctl — minimal terminal client for vnctlsd
//
// The server drives everything: login prompt, command menu, console stream.
// The client is a dumb pipe — either raw terminal mode + bidirectional TLS I/O
// or an SSH invocation of vnctlsd-ssh-bridge on the server.
//
// TLS usage:
//   vnctl -server foo.example.com:8443
//   vnctl -server foo.example.com:8443 -insecure
//   vnctl -server foo.example.com:8443 -cert client.crt -key client.key -ca ca.crt
//
// On Linux/macOS the equivalent without this binary:
//   socat $(tty),raw,echo=0 OPENSSL:foo.example.com:8443,verify=0
//
// This binary exists primarily for Windows compatibility, where socat is
// not available and raw terminal mode requires the Windows Console API
// (handled transparently by golang.org/x/term).

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	mode := flag.String("mode", "tls", "connection mode: tls or ssh")
	server := flag.String("server", "localhost:8443", "server `address` (host:port for tls, [user@]host for ssh)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	certFile := flag.String("cert", "", "client certificate `file` (PEM) for TLS client authentication")
	keyFile := flag.String("key", "", "client key `file` (PEM) for TLS client authentication")
	caFile := flag.String("ca", "", "CA certificate `file` (PEM) for server verification")
	proxy := flag.String("proxy", "", "proxy URL for TLS mode ([http://|https://]host[:port]); NO_PROXY still applies")
	insecureProxy := flag.Bool("insecure-proxy", false, "skip TLS certificate verification for an https:// proxy (does not affect verification of the target server)")
	verbose := flag.Bool("verbose", false, "print TLS handshake and certificate details")
	sshBin := flag.String("ssh-bin", defaultSSHBin, "SSH binary for -mode ssh")
	sshArgs := flag.String("ssh-args", "", "extra SSH arguments for -mode ssh, e.g. \"-p 2222 -J bastion\"")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\nFlags:\n", os.Args[0])
		for _, name := range []string{
			"mode", "server", "insecure", "cert", "key", "ca",
			"proxy", "insecure-proxy", "verbose", "ssh-bin", "ssh-args",
		} {
			if f := flag.Lookup(name); f != nil {
				fmt.Fprintf(os.Stderr, "  -%-10s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintln(os.Stderr)
	}
	flag.Parse()

	switch *mode {
	case "tls":
		runTLS(*server, *insecure, *certFile, *keyFile, *caFile, *proxy, *insecureProxy, *verbose)
	case "ssh":
		runSSH(*server, *sshBin, *sshArgs)
	default:
		fmt.Fprintf(os.Stderr, "vnctl: unknown -mode %q\n", *mode)
		os.Exit(1)
	}
}
