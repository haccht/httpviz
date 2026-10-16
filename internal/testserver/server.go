package testserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type Server struct {
	H1Addr    string // http://127.0.0.1:port
	H2Addr    string // https://127.0.0.1:port (HTTP/1.1 + HTTP/2 over TLS)
	H3Addr    string // https://127.0.0.1:port (HTTP/3 over QUIC)
	TLSConfig *tls.Config

	h1Listener net.Listener
	h2Listener net.Listener
	h3Conn     net.PacketConn

	h1Server *http.Server
	h2Server *http.Server
	h3Server *http3.Server

	wg sync.WaitGroup
}

// GenerateCert creates an in-memory self-signed certificate for localhost and 127.0.0.1.
func GenerateCert() (tls.Certificate, *tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"httpviz test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	return cert, tlsConfig, nil
}

// Start launches H1, H2, and H3 test servers on available localhost ports.
func Start() (*Server, error) {
	_, tlsConfig, err := GenerateCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Hello from httpviz test server! Method: %s, Path: %s\n", r.Method, r.URL.Path)
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Body-Len", fmt.Sprintf("%d", len(body)))
		if custom := r.Header.Get("X-Custom"); custom != "" {
			w.Header().Set("X-Echo-Custom", custom)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Echo: method=%s len=%d body=%s\n", r.Method, len(body), string(body))
	})

	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Transfer-Encoding", "chunked")
		flusher, ok := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		if ok {
			flusher.Flush()
		}

		chunks := []string{
			"First chunk of data\n",
			"Second chunk with more interesting details\n",
			"Final chunk before close\n",
		}

		for _, chunk := range chunks {
			time.Sleep(10 * time.Millisecond)
			_, _ = w.Write([]byte(chunk))
			if ok {
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		// Write 128KB
		buf := make([]byte, 128*1024)
		for i := range buf {
			buf[i] = byte('A' + (i % 26))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf)
	})

	mux.HandleFunc("/multiplex/", func(w http.ResponseWriter, r *http.Request) {
		// e.g. /multiplex/a.js, /multiplex/b.css
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Response for %s: %s\n", r.URL.Path, strings.Repeat("x", 500))
	})

	// 1. Plain HTTP/1.1 listener
	h1Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen H1: %w", err)
	}
	h1Server := &http.Server{Handler: mux}

	// 2. TLS HTTP/1.1 & HTTP/2 listener
	h2Ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		_ = h1Ln.Close()
		return nil, fmt.Errorf("failed to listen H2: %w", err)
	}
	h2Server := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(h2Server, &http2.Server{}); err != nil {
		_ = h1Ln.Close()
		_ = h2Ln.Close()
		return nil, fmt.Errorf("failed to configure http2: %w", err)
	}

	// 3. HTTP/3 UDP listener
	h3Conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = h1Ln.Close()
		_ = h2Ln.Close()
		return nil, fmt.Errorf("failed to listen H3: %w", err)
	}

	h3TLSConfig := tlsConfig.Clone()
	h3TLSConfig.NextProtos = []string{http3.NextProtoH3}
	h3Server := &http3.Server{
		Handler:   mux,
		TLSConfig: h3TLSConfig,
	}

	s := &Server{
		H1Addr:     fmt.Sprintf("http://%s", h1Ln.Addr().String()),
		H2Addr:     fmt.Sprintf("https://%s", h2Ln.Addr().String()),
		H3Addr:     fmt.Sprintf("https://%s", h3Conn.LocalAddr().String()),
		TLSConfig:  tlsConfig,
		h1Listener: h1Ln,
		h2Listener: h2Ln,
		h3Conn:     h3Conn,
		h1Server:   h1Server,
		h2Server:   h2Server,
		h3Server:   h3Server,
	}

	s.wg.Add(3)
	go func() {
		defer s.wg.Done()
		_ = h1Server.Serve(h1Ln)
	}()
	go func() {
		defer s.wg.Done()
		_ = h2Server.Serve(h2Ln)
	}()
	go func() {
		defer s.wg.Done()
		_ = h3Server.Serve(h3Conn)
	}()

	return s, nil
}

func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if s.h1Server != nil {
		_ = s.h1Server.Shutdown(ctx)
	}
	if s.h2Server != nil {
		_ = s.h2Server.Shutdown(ctx)
	}
	if s.h3Server != nil {
		_ = s.h3Server.Close()
	}
	if s.h3Conn != nil {
		_ = s.h3Conn.Close()
	}
	s.wg.Wait()
}
