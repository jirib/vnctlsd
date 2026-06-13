// vnctl — minimal TLS terminal client for vnctlsd
//
// The server drives everything: login prompt, command menu, console stream.
// The client is a dumb pipe — raw terminal mode + bidirectional TLS I/O.
//
// Usage:
//   vnctl -server avocado:8443
//   vnctl -server avocado:8443 -insecure
//   vnctl -server avocado:8443 -cert client.crt -key client.key -ca ca.crt
//
// On Linux/macOS the equivalent without this binary:
//   socat $(tty),raw,echo=0 OPENSSL:avocado:8443,verify=0
//
// This binary exists primarily for Windows compatibility, where socat is
// not available and raw terminal mode requires the Windows Console API
// (handled transparently by golang.org/x/term).

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

func main() {
	server  := flag.String("server",   "localhost:8443", "vnctlsd server address (host:port)")
	insecure := flag.Bool("insecure",  false,            "skip TLS certificate verification")
	certFile := flag.String("cert",    "",               "client certificate file (PEM)")
	keyFile  := flag.String("key",     "",               "client key file (PEM)")
	caFile   := flag.String("ca",      "",               "CA certificate file (PEM) for server verification")
	flag.Parse()

	// -- TLS config ----------------------------------------------------------

	tlsCfg := &tls.Config{
		InsecureSkipVerify: *insecure,
	}

	// Optional: load CA cert for server verification
	if *caFile != "" {
		caPEM, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read CA file %q: %v\n", *caFile, err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			fmt.Fprintf(os.Stderr, "error: no valid certificates found in %q\n", *caFile)
			os.Exit(1)
		}
		tlsCfg.RootCAs = pool
	}

	// Optional: mutual TLS (client certificate)
	if *certFile != "" || *keyFile != "" {
		if *certFile == "" || *keyFile == "" {
			fmt.Fprintln(os.Stderr, "error: -cert and -key must be used together")
			os.Exit(1)
		}
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot load client cert/key: %v\n", err)
			os.Exit(1)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// -- Connect -------------------------------------------------------------

	conn, err := tls.Dial("tcp", *server, tlsCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot connect to %s: %v\n", *server, err)
		os.Exit(1)
	}
	defer conn.Close()

	// -- Raw terminal mode ---------------------------------------------------
	// Switch stdin to raw mode so every keystroke is sent immediately without
	// local line buffering or echo.  The server handles all echo and editing.
	// On Windows golang.org/x/term handles the Console API differences.

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// stdin is a pipe or file — skip raw mode, just copy
		go io.Copy(conn, os.Stdin)
		io.Copy(os.Stdout, conn)
		return
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot set raw terminal mode: %v\n", err)
		os.Exit(1)
	}
	defer term.Restore(fd, oldState)

	// -- Bidirectional copy --------------------------------------------------
	// Two goroutines: server→stdout and stdin→server.
	// Either side closing ends the session.

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(conn, os.Stdin)
		done <- struct{}{}
	}()

	<-done
}
