package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

func runTLS(server string, insecure bool, certFile, keyFile, caFile string) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure, //nolint:gosec // flag-controlled, user's choice
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vnctl: cannot read CA file %q: %v\n", caFile, err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			fmt.Fprintf(os.Stderr, "vnctl: no valid certificates found in %q\n", caFile)
			os.Exit(1)
		}
		tlsCfg.RootCAs = pool
	}

	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			fmt.Fprintln(os.Stderr, "vnctl: -cert and -key must be used together")
			os.Exit(1)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vnctl: cannot load client cert/key: %v\n", err)
			os.Exit(1)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	conn, err := tls.Dial("tcp", server, tlsCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: cannot connect to %s: %v\n", server, err)
		os.Exit(1)
	}
	defer conn.Close()

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// stdin is a pipe or redirected file — skip raw mode, just copy
		go io.Copy(conn, os.Stdin) //nolint:errcheck
		io.Copy(os.Stdout, conn)   //nolint:errcheck
		return
	}

	// Switch stdin to raw mode so every keystroke is sent immediately without
	// local line buffering or echo.  The server handles all echo and editing.
	// On Windows golang.org/x/term handles the Console API differences.
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: cannot set raw terminal mode: %v\n", err)
		os.Exit(1)
	}
	defer term.Restore(fd, oldState)

	// Two goroutines: server→stdout and stdin→server.  Either side closing
	// ends the session.
	done := make(chan struct{}, 2)
	go func() { io.Copy(os.Stdout, conn); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(conn, os.Stdin); done <- struct{}{} }()  //nolint:errcheck
	<-done
}
