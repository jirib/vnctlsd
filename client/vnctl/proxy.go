package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const defaultProxyPort = "8080"
const defaultSocksPort = "1080"

func dialForTLS(server, explicitProxy string, insecureProxy bool) (net.Conn, string, error) {
	proxySpec, source := selectProxy(server, explicitProxy)
	if proxySpec == "" {
		conn, err := net.DialTimeout("tcp", server, 30*time.Second)
		return conn, "", err
	}

	proxyURL, err := parseProxyURL(proxySpec)
	if err != nil {
		return nil, "", err
	}

	conn, err := connectViaProxy(server, proxyURL, insecureProxy)
	if err != nil {
		return nil, "", err
	}
	return conn, fmt.Sprintf("%s (%s)", redactProxyURL(proxyURL), source), nil
}

func selectProxy(server, explicitProxy string) (string, string) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
	}
	if noProxyMatch(host, firstEnv("no_proxy", "NO_PROXY")) {
		return "", ""
	}
	if explicitProxy != "" {
		return explicitProxy, "-proxy"
	}
	if v := firstEnv("https_proxy", "HTTPS_PROXY"); v != "" {
		return v, "HTTPS_PROXY"
	}
	if v := firstEnv("all_proxy", "ALL_PROXY"); v != "" {
		return v, "ALL_PROXY"
	}
	return "", ""
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func parseProxyURL(spec string) (*url.URL, error) {
	if !strings.Contains(spec, "://") {
		spec = "http://" + spec
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("bad proxy URL %q: %w", spec, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks4", "socks4a", "socks5", "socks5h":
	default:
		u.Scheme = "http"
	}
	if u.Host == "" {
		return nil, fmt.Errorf("bad proxy URL %q: missing host", spec)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		host := u.Hostname()
		if host == "" {
			host = u.Host
		}
		port := defaultProxyPort
		if strings.HasPrefix(strings.ToLower(u.Scheme), "socks") {
			port = defaultSocksPort
		}
		u.Host = net.JoinHostPort(host, port)
	}
	return u, nil
}

func connectViaProxy(target string, proxyURL *url.URL, insecureProxy bool) (net.Conn, error) {
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https":
		conn, err := net.DialTimeout("tcp", proxyURL.Host, 30*time.Second)
		if err != nil {
			return nil, err
		}
		return connectViaHTTPProxy(conn, target, proxyURL, insecureProxy)
	case "socks4":
		return nil, fmt.Errorf("proxy scheme %q is recognized but not supported; use socks5:// or socks5h://", proxyURL.Scheme)
	case "socks4a":
		return nil, fmt.Errorf("proxy scheme %q is recognized but not supported; use socks5h://", proxyURL.Scheme)
	case "socks5":
		return connectViaSocks5(target, proxyURL, false)
	case "socks5h":
		return connectViaSocks5(target, proxyURL, true)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

func connectViaHTTPProxy(conn net.Conn, target string, proxyURL *url.URL, insecureProxy bool) (net.Conn, error) {
	if strings.EqualFold(proxyURL.Scheme, "https") {
		host := proxyURL.Hostname()
		tlsConn := tls.Client(conn, &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: insecureProxy, //nolint:gosec // flag-controlled, user's choice
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		token := proxyURL.User.Username() + ":" + password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(token)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	if br.Buffered() != 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy sent unexpected data after CONNECT response")
	}
	return conn, nil
}

type timeoutDialer struct{}

func (timeoutDialer) Dial(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, 30*time.Second)
}

func connectViaSocks5(target string, proxyURL *url.URL, remoteDNS bool) (net.Conn, error) {
	host, port, err := splitTarget(target)
	if err != nil {
		return nil, err
	}

	dialTarget := target
	if !remoteDNS {
		ip, err := resolveProxyTargetIP(host)
		if err != nil {
			return nil, err
		}
		dialTarget = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}

	var auth *xproxy.Auth
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		auth = &xproxy.Auth{
			User:     proxyURL.User.Username(),
			Password: password,
		}
	}
	dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, timeoutDialer{})
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", dialTarget)
}

func resolveProxyTargetIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	for _, ip := range ips {
		if v6 := ip.To16(); v6 != nil {
			return v6, nil
		}
	}
	return nil, fmt.Errorf("no usable address for %s", host)
}

func splitTarget(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target port %q", portStr)
	}
	return strings.Trim(host, "[]"), port, nil
}

func noProxyMatch(host, list string) bool {
	host = strings.Trim(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" || list == "" {
		return false
	}
	for _, item := range strings.Split(list, ",") {
		item = strings.Trim(strings.ToLower(item), " \t[]")
		item = strings.TrimSuffix(item, ".")
		if item == "" {
			continue
		}
		if item == "*" {
			return true
		}
		if strings.Contains(item, "/") {
			if ip := net.ParseIP(host); ip != nil {
				if _, network, err := net.ParseCIDR(item); err == nil && network.Contains(ip) {
					return true
				}
			}
			continue
		}
		itemHost, itemPort, hasPort := splitNoProxyHostPort(item)
		if hasPort {
			_, hostPort, err := net.SplitHostPort(host)
			if err != nil || hostPort != itemPort {
				continue
			}
		}
		if host == itemHost || strings.HasSuffix(host, "."+strings.TrimPrefix(itemHost, ".")) {
			return true
		}
	}
	return false
}

func splitNoProxyHostPort(item string) (string, string, bool) {
	host, port, err := net.SplitHostPort(item)
	if err == nil {
		return strings.Trim(host, "[]"), port, true
	}
	lastColon := strings.LastIndex(item, ":")
	if lastColon <= 0 || strings.Contains(item[:lastColon], ":") {
		return item, "", false
	}
	if _, err := strconv.Atoi(item[lastColon+1:]); err != nil {
		return item, "", false
	}
	return item[:lastColon], item[lastColon+1:], true
}

func redactProxyURL(u *url.URL) string {
	clone := *u
	if clone.User != nil {
		clone.User = url.User("xxxxx")
	}
	return clone.String()
}
