package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
		"all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY",
	} {
		t.Setenv(name, "")
	}
}

func TestSelectProxyExplicitStillHonorsNoProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("NO_PROXY", "direct.example.com")
	proxy, source := selectProxy("direct.example.com:8443", "http://proxy.example.com:8080")
	if proxy != "" || source != "" {
		t.Fatalf("proxy = %q/%q, want direct", proxy, source)
	}
}

func TestSelectProxyLowercaseEnvWins(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("https_proxy", "http://lower.example.com:8080")
	t.Setenv("HTTPS_PROXY", "http://upper.example.com:8080")
	proxy, source := selectProxy("target.example.com:8443", "")
	if proxy != "http://lower.example.com:8080" || source != "HTTPS_PROXY" {
		t.Fatalf("proxy = %q/%q", proxy, source)
	}
}

func TestSelectProxyFallsBackToAllProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("ALL_PROXY", "http://all.example.com:8080")
	proxy, source := selectProxy("target.example.com:8443", "")
	if proxy != "http://all.example.com:8080" || source != "ALL_PROXY" {
		t.Fatalf("proxy = %q/%q", proxy, source)
	}
}

func TestNoProxyMatchesDomainIPAndCIDR(t *testing.T) {
	if !noProxyMatch("api.example.com", ".example.com") {
		t.Fatal("domain suffix did not match")
	}
	if !noProxyMatch("192.168.4.5", "192.168.0.0/16") {
		t.Fatal("CIDR did not match")
	}
	if !noProxyMatch("2001:db8::1", "2001:db8::/32") {
		t.Fatal("IPv6 CIDR did not match")
	}
	if noProxyMatch("api.example.net", ".example.com") {
		t.Fatal("unrelated domain matched")
	}
}

func TestParseProxyURLDefaultsToHTTPAndPort(t *testing.T) {
	u, err := parseProxyURL("proxy.example.com")
	if err != nil {
		t.Fatalf("parse proxy: %v", err)
	}
	if u.Scheme != "http" {
		t.Fatalf("scheme = %q, want http", u.Scheme)
	}
	if u.Host != "proxy.example.com:8080" {
		t.Fatalf("host = %q, want proxy.example.com:8080", u.Host)
	}
}

func TestParseProxyURLAcceptsSocksWithDefaultPort(t *testing.T) {
	u, err := parseProxyURL("socks5h://proxy.example.com")
	if err != nil {
		t.Fatalf("parse socks proxy: %v", err)
	}
	if u.Scheme != "socks5h" {
		t.Fatalf("scheme = %q, want socks5h", u.Scheme)
	}
	if u.Host != "proxy.example.com:1080" {
		t.Fatalf("host = %q, want proxy.example.com:1080", u.Host)
	}
}

func TestConnectViaHTTPProxyRejectsUntrustedCertByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}

	_, err = connectViaHTTPProxy(conn, "target.example.com:443", proxyURL, false)
	if err == nil {
		t.Fatal("expected certificate verification failure with insecureProxy=false, got nil error")
	}
}

func TestConnectViaHTTPProxyInsecureProxySkipsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}

	_, err = connectViaHTTPProxy(conn, "target.example.com:443", proxyURL, true)
	if err != nil {
		t.Fatalf("expected insecureProxy=true to skip cert verification, got: %v", err)
	}
}
