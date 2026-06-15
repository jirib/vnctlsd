// vnctl — minimal terminal client for vnctlsd
//
// The server drives everything: login prompt, command menu, console stream.
// The client is a dumb pipe — either raw terminal mode + bidirectional TLS I/O
// or an OpenSSH subsystem invocation.
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
	// SSH-mode flags are intentionally omitted from the default usage output.
	// They are available but not advertised; see ssh.go for details.
	mode     := flag.String("mode", "tls", "")
	server   := flag.String("server", "localhost:8443", "server `address` (host:port for tls, [user@]host for ssh)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	certFile := flag.String("cert", "", "client certificate `file` (PEM)")
	keyFile  := flag.String("key",  "", "client key `file` (PEM)")
	caFile   := flag.String("ca",   "", "CA certificate `file` (PEM) for server verification")
	sshArgs  := flag.String("ssh-args", defaultSSHArgs, "")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\nFlags:\n", os.Args[0])
		for _, name := range []string{"server", "insecure", "cert", "key", "ca"} {
			if f := flag.Lookup(name); f != nil {
				fmt.Fprintf(os.Stderr, "  -%-10s %s\n", f.Name, f.Usage)
			}
		}
		fmt.Fprintln(os.Stderr)
	}
	flag.Parse()

	switch *mode {
	case "tls":
		runTLS(*server, *insecure, *certFile, *keyFile, *caFile)
	case "ssh":
		runSSH(*server, *sshArgs)
	default:
		fmt.Fprintf(os.Stderr, "vnctl: unknown -mode %q\n", *mode)
		os.Exit(1)
	}
}
