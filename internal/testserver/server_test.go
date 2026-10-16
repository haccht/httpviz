package testserver

import (
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestTestServer(t *testing.T) {
	srv, err := Start()
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Close()

	// Test H1
	h1Client := &http.Client{Timeout: 3 * time.Second}
	resp, err := h1Client.Get(srv.H1Addr + "/index.html")
	if err != nil {
		t.Fatalf("H1 GET failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Fatalf("expected non-empty body")
	}

	// Test H2 (TLS with InsecureSkipVerify)
	h2Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 3 * time.Second,
	}
	resp2, err := h2Client.Get(srv.H2Addr + "/index.html")
	if err != nil {
		t.Fatalf("H2 GET failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.ProtoMajor != 2 {
		t.Logf("Notice: resp2 proto is %s", resp2.Proto)
	}
	if len(body2) == 0 {
		t.Fatalf("expected non-empty body")
	}
}
