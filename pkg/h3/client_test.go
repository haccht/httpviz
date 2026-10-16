package h3

import (
	"testing"
	"time"

	"github.com/haccht/httpviz/internal/testserver"
)

func TestH3Client(t *testing.T) {
	srv, err := testserver.Start()
	if err != nil {
		t.Fatalf("failed to start testserver: %v", err)
	}
	defer srv.Close()

	events, err := Run([]string{srv.H3Addr + "/index.html"}, Options{
		Insecure: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("H3 Run failed: %v", err)
	}
	t.Logf("Got %d events", len(events))
	for _, e := range events {
		t.Logf("Event: type=%s dir=%s len=%d subevents=%d", e.FrameType, e.Direction, e.Length, len(e.SubEvents))
	}

	hasPacket := false
	for _, e := range events {
		if e.FrameType == "QUIC_PACKET" {
			hasPacket = true
			break
		}
	}

	if !hasPacket {
		t.Errorf("expected QUIC_PACKET events, got none")
	}
}
