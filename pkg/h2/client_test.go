package h2

import (
	"testing"
	"time"

	"github.com/haccht/httpviz/internal/testserver"
)

func TestH2Client(t *testing.T) {
	srv, err := testserver.Start()
	if err != nil {
		t.Fatalf("failed to start testserver: %v", err)
	}
	defer srv.Close()

	events, err := Run([]string{
		srv.H2Addr + "/index.html",
		srv.H2Addr + "/large",
	}, Options{
		Insecure: true,
		Timeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("H2 Run failed: %v", err)
	}

	hasMagic := false
	hasSettings := false
	hasHeaders := false
	hasData := false
	streamsSeen := make(map[uint32]bool)

	for _, e := range events {
		streamsSeen[e.StreamID] = true
		switch e.FrameType {
		case "MAGIC":
			hasMagic = true
		case "SETTINGS":
			hasSettings = true
		case "HEADERS":
			hasHeaders = true
		case "DATA":
			hasData = true
		}
	}

	if !hasMagic {
		t.Errorf("missing MAGIC frame event")
	}
	if !hasSettings {
		t.Errorf("missing SETTINGS frame event")
	}
	if !hasHeaders {
		t.Errorf("missing HEADERS frame event")
	}
	if !hasData {
		t.Errorf("missing DATA frame event")
	}
	if !streamsSeen[1] || !streamsSeen[3] {
		t.Errorf("expected multiplexed streams 1 and 3, got: %v", streamsSeen)
	}
}

