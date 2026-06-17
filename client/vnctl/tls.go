package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

func runTLS(server string, insecure bool, certFile, keyFile, caFile, proxyFlag string,
	insecureProxy, verbose bool) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
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

	var clientLeaf *x509.Certificate
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
		clientLeaf = parseClientLeaf(cert.Certificate)
		cert.Leaf = clientLeaf
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	rawConn, proxyInfo, err := dialForTLS(server, proxyFlag, insecureProxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: cannot connect to %s: %v\n", server, err)
		os.Exit(1)
	}
	defer rawConn.Close()

	tlsCfg = tlsCfg.Clone()
	if tlsCfg.ServerName == "" {
		host, _, err := net.SplitHostPort(server)
		if err == nil {
			tlsCfg.ServerName = host
		}
	}

	conn := tls.Client(rawConn, tlsCfg)
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "vnctl: TLS handshake with %s failed: %v\n", server, err)
		os.Exit(1)
	}
	if verbose {
		if proxyInfo == "" {
			fmt.Fprintln(os.Stderr, "vnctl: proxy: direct")
		} else {
			fmt.Fprintf(os.Stderr, "vnctl: proxy: %s\n", proxyInfo)
		}
		printTLSState(os.Stderr, server, conn.ConnectionState(), clientLeaf, certFile, caFile, insecure)
	}

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

func parseClientLeaf(chain [][]byte) *x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil
	}
	return cert
}

func printTLSState(w io.Writer, server string, state tls.ConnectionState,
	clientLeaf *x509.Certificate, certFile, caFile string, insecure bool) {
	fmt.Fprintf(w, "vnctl: TLS connected to %s\n", server)
	fmt.Fprintf(w, "vnctl:   version: %s\n", tlsVersionName(state.Version))
	fmt.Fprintf(w, "vnctl:   cipher: %s\n", tls.CipherSuiteName(state.CipherSuite))
	if state.ServerName != "" {
		fmt.Fprintf(w, "vnctl:   server name: %s\n", state.ServerName)
	}
	if state.NegotiatedProtocol != "" {
		fmt.Fprintf(w, "vnctl:   ALPN: %s\n", state.NegotiatedProtocol)
	}
	fmt.Fprintf(w, "vnctl:   verification: %s\n", verificationSummary(state, caFile, insecure))

	if len(state.PeerCertificates) == 0 {
		fmt.Fprintln(w, "vnctl:   server certificate: none presented")
	} else {
		printCertSummary(w, "server certificate", state.PeerCertificates[0])
	}

	if clientLeaf == nil {
		if certFile == "" {
			fmt.Fprintln(w, "vnctl:   client certificate: none configured")
		} else {
			fmt.Fprintf(w, "vnctl:   client certificate: configured from %s\n", certFile)
		}
		return
	}
	printCertSummary(w, "client certificate", clientLeaf)
}

func printCertSummary(w io.Writer, label string, cert *x509.Certificate) {
	fmt.Fprintf(w, "vnctl:   %s:\n", label)
	fmt.Fprintf(w, "vnctl:     subject: %s\n", cert.Subject.String())
	fmt.Fprintf(w, "vnctl:     issuer: %s\n", cert.Issuer.String())
	fmt.Fprintf(w, "vnctl:     serial: %s\n", cert.SerialNumber.String())
	fmt.Fprintf(w, "vnctl:     valid: %s to %s\n",
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339))
	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(w, "vnctl:     DNS names: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, 0, len(cert.IPAddresses))
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Fprintf(w, "vnctl:     IP addresses: %s\n", strings.Join(ips, ", "))
	}
}

func verificationSummary(state tls.ConnectionState, caFile string, insecure bool) string {
	if insecure {
		return "disabled by -insecure"
	}
	source := "system roots"
	if caFile != "" {
		source = caFile
	}
	if len(state.VerifiedChains) == 0 {
		return "no verified chains reported"
	}
	return fmt.Sprintf("ok (%d chain(s), roots: %s)", len(state.VerifiedChains), source)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", version)
	}
}
