package h1

import (
	"testing"
	"time"

	"github.com/haccht/httpviz/internal/testserver"
)

func TestH1Client(t *testing.T) {
	srv, err := testserver.Start()
	if err != nil {
		t.Fatalf("failed to start testserver: %v", err)
	}
	defer srv.Close()

	// 1. Test regular GET and Keep-Alive across 2 URLs
	var infos []string
	events, err := Run([]string{srv.H1Addr + "/index.html", srv.H1Addr + "/index.html"}, Options{
		Timeout: 3 * time.Second,
		OnInfo: func(msg string, _ time.Duration) {
			infos = append(infos, msg)
		},
	})
	if err != nil {
		t.Fatalf("H1 Run failed: %v", err)
	}

	hasReqLine := false
	hasStatusLine := false
	hasHeaders := false
	for _, e := range events {
		if e.FrameType == "REQUEST_LINE" {
			hasReqLine = true
		}
		if e.FrameType == "STATUS_LINE" {
			hasStatusLine = true
		}
		if e.FrameType == "HEADERS" {
			hasHeaders = true
		}
	}
	if !hasReqLine || !hasStatusLine || !hasHeaders {
		t.Errorf("missing expected H1 events: reqLine=%v, statusLine=%v, headers=%v", hasReqLine, hasStatusLine, hasHeaders)
	}

	// 2. Test Chunked GET
	chunkEvents, err := Run([]string{srv.H1Addr + "/chunked"}, Options{
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("H1 Chunked Run failed: %v", err)
	}

	chunkCount := 0
	hasFin := false
	for _, e := range chunkEvents {
		if e.FrameType == "CHUNK" {
			chunkCount++
			for _, d := range e.Details {
				if d == "size=0B, chunk #4, [FIN]" || (len(d) > 0 && d[len(d)-5:] == "[FIN]") {
					hasFin = true
				}
			}
		}
	}
	if chunkCount == 0 {
		t.Errorf("expected chunk events, got 0")
	}
	if !hasFin {
		t.Errorf("expected [FIN] chunk event")
	}
}
