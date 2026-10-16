package event

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"
)

// ResolveDNSIfNeeded resolves the hostname if it is not an IP literal, reporting the lookup duration via onInfo.
// It returns the resolved dial address (ip:port) if resolution succeeded, or the original hostPort as fallback.
func ResolveDNSIfNeeded(u *url.URL, hostPort string, timeout time.Duration, connStart time.Time, onInfo func(string, time.Duration)) string {
	hostname := u.Hostname()
	if hostname == "" || net.ParseIP(hostname) != nil {
		return hostPort
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dnsStart := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	dnsDur := time.Since(dnsStart)
	if err != nil || len(addrs) == 0 {
		return hostPort
	}

	if onInfo != nil {
		onInfo(
			fmt.Sprintf("* DNS Lookup: %s -> %s (%.1fms)", hostname, addrs[0], float64(dnsDur.Microseconds())/1000.0),
			time.Since(connStart),
		)
	}
	return net.JoinHostPort(addrs[0], port)
}

// DialTCPOrTLS dials a TCP or TLS connection while measuring and reporting DNS, TCP, and TLS handshake phases.
// If requireALPN is non-empty, it verifies that the negotiated ALPN matches requireALPN.
func DialTCPOrTLS(u *url.URL, scheme, hostPort string, nextProtos []string, requireALPN string, opts Options) (net.Conn, string, time.Time, error) {
	timeout := opts.EffectiveTimeout()
	connStart := time.Now()

	dialAddr := ResolveDNSIfNeeded(u, hostPort, timeout, connStart, opts.OnInfo)

	dialer := &net.Dialer{Timeout: timeout}
	tcpStart := time.Now()
	rawConn, err := dialer.Dial("tcp", dialAddr)
	tcpDur := time.Since(tcpStart)
	if err != nil {
		if scheme == "https" {
			return nil, "", connStart, fmt.Errorf("tls dial to %s failed: %w", hostPort, err)
		}
		return nil, "", connStart, fmt.Errorf("tcp dial to %s failed: %w", hostPort, err)
	}

	if scheme != "https" {
		if opts.OnInfo != nil {
			opts.OnInfo(
				fmt.Sprintf("* Connected to %s (TCP, %.1fms)", rawConn.RemoteAddr().String(), float64(tcpDur.Microseconds())/1000.0),
				time.Since(connStart),
			)
		}
		return rawConn, "", connStart, nil
	}

	if opts.OnInfo != nil {
		opts.OnInfo(
			fmt.Sprintf("* TCP Connected to %s (%.1fms)", rawConn.RemoteAddr().String(), float64(tcpDur.Microseconds())/1000.0),
			time.Since(connStart),
		)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.Insecure,
		NextProtos:         nextProtos,
		ServerName:         u.Hostname(),
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	_ = rawConn.SetDeadline(time.Now().Add(timeout))
	tlsStart := time.Now()
	err = tlsConn.Handshake()
	tlsDur := time.Since(tlsStart)
	_ = rawConn.SetDeadline(time.Time{})
	if err != nil {
		_ = rawConn.Close()
		return nil, "", connStart, fmt.Errorf("tls dial to %s failed: %w", hostPort, err)
	}

	cs := tlsConn.ConnectionState()
	proto := tls.VersionName(cs.Version)
	cipher := tls.CipherSuiteName(cs.CipherSuite)
	alpn := cs.NegotiatedProtocol

	if requireALPN != "" && alpn != requireALPN {
		_ = tlsConn.Close()
		return nil, "", connStart, fmt.Errorf("server did not negotiate HTTP/2 (ALPN: %q)", alpn)
	}

	if alpn == "" {
		alpn = "http/1.1"
	}

	if opts.OnInfo != nil {
		opts.OnInfo(
			fmt.Sprintf("* TLS Handshake: %s, Cipher: %s (%.1fms)", proto, cipher, float64(tlsDur.Microseconds())/1000.0),
			time.Since(connStart),
		)
		opts.OnInfo(
			fmt.Sprintf("* Connected to %s (%s, ALPN: %s)", tlsConn.RemoteAddr().String(), proto, alpn),
			time.Since(connStart),
		)
	}

	return tlsConn, alpn, connStart, nil
}
