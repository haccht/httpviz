package har

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"github.com/haccht/httpviz/pkg/render"
)

func TestHARRun_H1_H2_H3(t *testing.T) {
	b64Body := base64.StdEncoding.EncodeToString([]byte("decoded-base64-response-payload"))
	sampleHAR := `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "startedDateTime": "2026-10-16T12:00:00.000Z",
        "time": 45.0,
        "serverIPAddress": "93.184.215.14",
        "_securityDetails": {
          "protocol": "TLS 1.3",
          "cipher": "TLS_AES_128_GCM_SHA256"
        },
        "request": {
          "method": "GET",
          "url": "https://example.com/index.html",
          "httpVersion": "h2",
          "headers": [
            {"name": ":method", "value": "GET"},
            {"name": "user-agent", "value": "Mozilla/5.0"},
            {"name": "accept", "value": "text/html"}
          ],
          "headersSize": 42,
          "bodySize": 0
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "h2",
          "headers": [
            {"name": "content-type", "value": "text/html"}
          ],
          "headersSize": 38,
          "bodySize": 31,
          "content": {
            "size": 31,
            "mimeType": "text/html",
            "text": "` + b64Body + `",
            "encoding": "base64"
          }
        },
        "timings": {
          "blocked": 0,
          "dns": 2.5,
          "connect": 20.0,
          "ssl": 12.0,
          "send": 1.0,
          "wait": 15.0,
          "receive": 6.5
        }
      },
      {
        "startedDateTime": "2026-10-16T12:00:00.025Z",
        "time": 20.0,
        "serverIPAddress": "93.184.215.14",
        "request": {
          "method": "POST",
          "url": "http://example.com/api/submit",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {"name": "Host", "value": "example.com"},
            {"name": "Content-Type", "value": "application/json"}
          ],
          "headersSize": 64,
          "bodySize": 15,
          "postData": {
            "mimeType": "application/json",
            "text": "{\"hello\":\"har\"}"
          }
        },
        "response": {
          "status": 201,
          "statusText": "Created",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {"name": "Content-Type", "value": "application/json"}
          ],
          "headersSize": 48,
          "bodySize": 12,
          "content": {
            "size": 12,
            "mimeType": "application/json",
            "text": "{\"ok\":true}"
          }
        },
        "timings": {
          "dns": -1,
          "connect": 5.0,
          "ssl": -1,
          "send": 1.0,
          "wait": 10.0,
          "receive": 4.0
        }
      },
      {
        "startedDateTime": "2026-10-16T12:00:00.030Z",
        "time": 15.0,
        "serverIPAddress": "93.184.215.14",
        "request": {
          "method": "GET",
          "url": "https://example.com/app.js",
          "httpVersion": "h3",
          "headers": [
            {"name": "user-agent", "value": "Mozilla/5.0"}
          ],
          "headersSize": 30,
          "bodySize": 0
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "h3",
          "headers": [
            {"name": "content-type", "value": "application/javascript"}
          ],
          "headersSize": 28,
          "bodySize": 1024,
          "content": {
            "size": 1024,
            "mimeType": "application/javascript"
          }
        },
        "timings": {
          "dns": -1,
          "connect": 8.0,
          "ssl": 8.0,
          "send": 1.0,
          "wait": 4.0,
          "receive": 2.0
        }
      }
    ]
  }
}`

	var infos []string
	events, err := Run(strings.NewReader(sampleHAR), event.Options{
		ShowBody:  true,
		BodyLimit: 200,
		OnInfo: func(msg string, _ time.Duration) {
			infos = append(infos, msg)
		},
	})
	if err != nil {
		t.Fatalf("har.Run failed: %v", err)
	}

	infoJoined := strings.Join(infos, "\n")
	if !strings.Contains(infoJoined, "* DNS Lookup: example.com -> 93.184.215.14") {
		t.Errorf("expected DNS Lookup info, got:\n%s", infoJoined)
	}
	if !strings.Contains(infoJoined, "* TCP Connected to 93.184.215.14:443 (8.0ms)") {
		t.Errorf("expected TCP Connected info (20 - 12 = 8ms), got:\n%s", infoJoined)
	}
	if !strings.Contains(infoJoined, "* TLS Handshake: TLSv1.3, Cipher: TLS_AES_128_GCM_SHA256 (12.0ms)") {
		t.Errorf("expected TLS Handshake info, got:\n%s", infoJoined)
	}
	if !strings.Contains(infoJoined, "* Connected to 93.184.215.14:443 (QUIC, ALPN: h3, 8.0ms)") {
		t.Errorf("expected QUIC connected info, got:\n%s", infoJoined)
	}

	var treeOut strings.Builder
	render.RenderTree(&treeOut, events)
	treeStr := treeOut.String()

	if !strings.Contains(treeStr, "decoded-base64-response-payload") {
		t.Errorf("expected base64 decoded payload in tree output, got:\n%s", treeStr)
	}
	if !strings.Contains(treeStr, "Static Index: 2") {
		t.Errorf("expected HPACK Static Index annotation in H2 entry, got:\n%s", treeStr)
	}
	if !strings.Contains(treeStr, `"POST /api/submit HTTP/1.1"`) {
		t.Errorf("expected H1 REQUEST_LINE in tree output, got:\n%s", treeStr)
	}

	timelineStr := render.FormatTimelineColored(events, false)
	if !strings.Contains(timelineStr, "Stream 1") || !strings.Contains(timelineStr, "Stream 2") || !strings.Contains(timelineStr, "Stream 5") {
		t.Errorf("expected multiple streams in timeline output, got:\n%s", timelineStr)
	}
}

func TestHARRun_ProtocolFilter(t *testing.T) {
	sampleHAR := `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "request": {"method": "GET", "url": "http://example.com/a", "httpVersion": "HTTP/1.1"},
        "response": {"status": 200, "httpVersion": "HTTP/1.1"}
      },
      {
        "request": {"method": "GET", "url": "https://example.com/b", "httpVersion": "h2"},
        "response": {"status": 200, "httpVersion": "h2"}
      }
    ]
  }
}`
	events, err := Run(strings.NewReader(sampleHAR), event.Options{ProtocolFilter: "h2"})
	if err != nil {
		t.Fatalf("har.Run with h2 filter failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (H2 req & resp headers), got %d", len(events))
	}
	if events[0].FrameType != event.FrameHeaders || events[1].FrameType != event.FrameHeaders {
		t.Errorf("unexpected event types: %+v", events)
	}

	_, err = Run(strings.NewReader(sampleHAR), event.Options{ProtocolFilter: "h3"})
	if err == nil {
		t.Errorf("expected error when no entries match filter h3")
	}
}
