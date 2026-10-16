package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/haccht/httpviz/internal/testserver"
)

func TestE2EBinaries(t *testing.T) {
	srv, err := testserver.Start()
	if err != nil {
		t.Fatalf("failed to start testserver: %v", err)
	}
	defer srv.Close()

	// Also start a TLS HTTP/1.1-only server to test ALPN fallback to http/1.1
	h1TLSConfig := srv.TLSConfig.Clone()
	h1TLSConfig.NextProtos = []string{"http/1.1"}
	h1TLSLn, err := tls.Listen("tcp", "127.0.0.1:0", h1TLSConfig)
	if err != nil {
		t.Fatalf("failed to start TLS H1 listener: %v", err)
	}
	defer h1TLSLn.Close()
	h1TLSServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, "Hello TLS H1")
		}),
	}
	go func() {
		_ = h1TLSServer.Serve(h1TLSLn)
	}()
	defer h1TLSServer.Close()
	h1TLSAddr := fmt.Sprintf("https://%s", h1TLSLn.Addr().String())

	binPath := filepath.Join(t.TempDir(), "httpviz")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build httpviz: %v\n%s", err, string(out))
	}

	// 1. Test H1 (explicit --h1)
	t.Run("H1_Explicit", func(t *testing.T) {
		cmd := exec.Command(binPath, "--h1", srv.H1Addr+"/chunked")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz --h1 failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "REQUEST_LINE") || !strings.Contains(res, "CHUNK") {
			t.Errorf("expected REQUEST_LINE and CHUNK in H1 output, got:\n%s", res)
		}
	})

	// 2. Test H1 forced over HTTPS (against H2-capable server)
	t.Run("H1_ForcedOverTLS", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", "--h1", srv.H2Addr+"/index.html")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz -k --h1 failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "ALPN: http/1.1") || !strings.Contains(res, "REQUEST_LINE") {
			t.Errorf("expected ALPN: http/1.1 and REQUEST_LINE in forced H1 output, got:\n%s", res)
		}
	})

	// 3. Test Auto-Negotiation -> H2 (when server supports h2)
	t.Run("Negotiate_H2", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", srv.H2Addr+"/index.html")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz -k failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "ALPN: h2") || !strings.Contains(res, "MAGIC") || !strings.Contains(res, "SETTINGS") || !strings.Contains(res, "HEADERS") {
			t.Errorf("expected ALPN: h2, MAGIC, SETTINGS, and HEADERS in negotiated H2 output, got:\n%s", res)
		}
	})

	// 4. Test Auto-Negotiation -> H1 (when TLS server only supports http/1.1)
	t.Run("Negotiate_TLS_H1", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", h1TLSAddr+"/index.html")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz -k (TLS H1) failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "ALPN: http/1.1") || !strings.Contains(res, "REQUEST_LINE") || !strings.Contains(res, "STATUS_LINE") {
			t.Errorf("expected ALPN: http/1.1, REQUEST_LINE, and STATUS_LINE in negotiated TLS H1 output, got:\n%s", res)
		}
	})

	// 5. Test Explicit --h2
	t.Run("H2_Explicit", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", "--h2", srv.H2Addr+"/index.html")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz -k --h2 failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "MAGIC") || !strings.Contains(res, "SETTINGS") || !strings.Contains(res, "HEADERS") {
			t.Errorf("expected MAGIC, SETTINGS, and HEADERS in explicit --h2 output, got:\n%s", res)
		}
	})

	// 6. Test Explicit --h2 against H1-only server fails
	t.Run("H2_Explicit_FailsOnH1Server", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", "--h2", h1TLSAddr+"/index.html")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err == nil {
			t.Fatalf("expected httpviz -k --h2 against H1-only server to fail, but succeeded:\n%s", out.String())
		}
	})

	// 7. Test H2 Timeline with multiple URLs (Stream 1 & Stream 3)
	t.Run("H2_Timeline", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", "--timeline", srv.H2Addr+"/index.html", srv.H2Addr+"/large")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz --timeline failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "Time (ms)") || !strings.Contains(res, "Stream 1") || !strings.Contains(res, "Stream 3") {
			t.Errorf("expected Time (ms), Stream 1, and Stream 3 in timeline output, got:\n%s", res)
		}
	})

	// 8. Test H3
	t.Run("H3", func(t *testing.T) {
		time.Sleep(50 * time.Millisecond)
		cmd := exec.Command(binPath, "-k", "--h3", srv.H3Addr+"/index.html")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz --h3 failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "QUIC_PACKET") {
			t.Errorf("expected QUIC_PACKET in H3 output")
		}
	})

	// 9. Test -d (auto POST) and -X PUT across H1 and H2
	t.Run("RequestMethodAndData", func(t *testing.T) {
		// H2 with -d (auto POST)
		cmd := exec.Command(binPath, "-k", "-d", "hello=httpviz", srv.H2Addr+"/echo")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz -k -d failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, ":method: POST  [Static Index: 3]") {
			t.Errorf("expected :method: POST [Static Index: 3] in H2 output, got:\n%s", res)
		}
		if !strings.Contains(res, "──> [Stream 1] DATA             (len=13, flags=0x1 [END_STREAM])") {
			t.Errorf("expected outbound DATA frame on Stream 1, got:\n%s", res)
		}

		// H1 with -X PUT -d
		cmdH1 := exec.Command(binPath, "-X", "PUT", "-d", "payload123", srv.H1Addr+"/echo")
		var outH1 bytes.Buffer
		cmdH1.Stdout = &outH1
		cmdH1.Stderr = &outH1
		if err := cmdH1.Run(); err != nil {
			t.Fatalf("httpviz -X PUT -d failed: %v, out: %s", err, outH1.String())
		}
		resH1 := outH1.String()
		if !strings.Contains(resH1, `"PUT /echo HTTP/1.1"`) || !strings.Contains(resH1, "──> [Stream 0] DATA             (len=10)") {
			t.Errorf("expected PUT request line and outbound DATA in H1 output, got:\n%s", resH1)
		}
	})

	// 10. Test -H custom headers and HPACK Dynamic Table reuse across 2 requests
	t.Run("CustomHeaders_And_HPACKDynamicTable", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k",
			"-H", "X-Custom: super-secret-token-value",
			srv.H2Addr+"/echo",
			srv.H2Addr+"/echo",
		)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz -H failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "x-custom: super-secret-token-value  [Literal, Indexed -> Dynamic Index:") {
			t.Errorf("expected 1st request x-custom to be Literal, Indexed -> Dynamic Index, got:\n%s", res)
		}
		if !strings.Contains(res, "x-custom: super-secret-token-value  [Dynamic Index:") {
			t.Errorf("expected 2nd request x-custom to reuse Dynamic Index, got:\n%s", res)
		}
		if !strings.Contains(res, "x-echo-custom: super-secret-token-value") {
			t.Errorf("expected echoed x-echo-custom header in response, got:\n%s", res)
		}
	})

	// 11. Test --window-size and --ping
	t.Run("WindowSize_And_Ping", func(t *testing.T) {
		cmd := exec.Command(binPath, "-k", "--window-size", "16384", "--ping", srv.H2Addr+"/large")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("httpviz --window-size --ping failed: %v, out: %s", err, out.String())
		}
		res := out.String()
		if !strings.Contains(res, "INITIAL_WINDOW_SIZE: 16384") {
			t.Errorf("expected INITIAL_WINDOW_SIZE: 16384 in SETTINGS, got:\n%s", res)
		}
		if !strings.Contains(res, "──> [Stream 0] PING") || !strings.Contains(res, "RTT:") {
			t.Errorf("expected PING and PING ACK with RTT, got:\n%s", res)
		}
		if !strings.Contains(res, "──> [Stream 1] WINDOW_UPDATE") {
			t.Errorf("expected client WINDOW_UPDATE on Stream 1 for /large with 16KB window, got:\n%s", res)
		}
	})

	// 12. Test --body [bytes] and -d @file across H1 and H2
	t.Run("ShowBody_And_DataFile", func(t *testing.T) {
		// Create a temporary file for -d @file testing
		dataFile := filepath.Join(t.TempDir(), "payload.txt")
		payloadContent := "file-payload-line1\nfile-payload-line2-abcdefghijklmnopqrstuvwxyz0123456789"
		if err := os.WriteFile(dataFile, []byte(payloadContent), 0600); err != nil {
			t.Fatalf("failed to write temp data file: %v", err)
		}

		// H2 with -d @file and --body 25 (space-separated byte limit)
		cmdH2Limit := exec.Command(binPath, "-k", "-d", "@"+dataFile, "--body", "25", srv.H2Addr+"/echo")
		var outH2Limit bytes.Buffer
		cmdH2Limit.Stdout = &outH2Limit
		cmdH2Limit.Stderr = &outH2Limit
		if err := cmdH2Limit.Run(); err != nil {
			t.Fatalf("httpviz -k -d @file --body 25 failed: %v, out: %s", err, outH2Limit.String())
		}
		resH2Limit := outH2Limit.String()
		if !strings.Contains(resH2Limit, "Payload (25/74B):") || !strings.Contains(resH2Limit, "... (truncated)") {
			t.Errorf("expected 25/74B truncated payload in H2 --body 25 output, got:\n%s", resH2Limit)
		}

		// H2 with -d @file and --body 0 (full payload, no truncation)
		cmdH2Full := exec.Command(binPath, "-k", "-d", "@"+dataFile, "--body", "0", srv.H2Addr+"/echo")
		var outH2Full bytes.Buffer
		cmdH2Full.Stdout = &outH2Full
		cmdH2Full.Stderr = &outH2Full
		if err := cmdH2Full.Run(); err != nil {
			t.Fatalf("httpviz -k -d @file --body 0 failed: %v, out: %s", err, outH2Full.String())
		}
		resH2Full := outH2Full.String()
		if !strings.Contains(resH2Full, "file-payload-line2-abcdefghijklmnopqrstuvwxyz0123456789") || strings.Contains(resH2Full, "... (truncated)") {
			t.Errorf("expected full payload without truncation in --body 0 output, got:\n%s", resH2Full)
		}

		// H1 chunked with --body (default 200B, chunks are small so shown in full)
		cmdH1 := exec.Command(binPath, "--body", srv.H1Addr+"/chunked")
		var outH1 bytes.Buffer
		cmdH1.Stdout = &outH1
		cmdH1.Stderr = &outH1
		if err := cmdH1.Run(); err != nil {
			t.Fatalf("httpviz --body chunked failed: %v, out: %s", err, outH1.String())
		}
		resH1 := outH1.String()
		if !strings.Contains(resH1, "Payload: First chunk of data") || !strings.Contains(resH1, "Payload: Final chunk before close") {
			t.Errorf("expected chunk Payloads in H1 --body output, got:\n%s", resH1)
		}
	})

	// 13. Test Handshake Details, Color Flag (--color=always / --color=never), and --h1 --ping notice
	t.Run("Color_Handshake_And_PingNotice", func(t *testing.T) {
		// --color=always with H2 should contain ANSI escape codes and TCP/TLS handshake phase lines
		cmdColor := exec.Command(binPath, "-k", "--color=always", srv.H2Addr+"/index.html")
		var outColor bytes.Buffer
		cmdColor.Stdout = &outColor
		cmdColor.Stderr = &outColor
		if err := cmdColor.Run(); err != nil {
			t.Fatalf("httpviz --color=always failed: %v, out: %s", err, outColor.String())
		}
		resColor := outColor.String()
		if !strings.Contains(resColor, "\x1b[") {
			t.Errorf("expected ANSI escape sequences with --color=always, got:\n%s", resColor)
		}
		if !strings.Contains(resColor, "* TCP Connected to") || !strings.Contains(resColor, "* TLS Handshake:") || !strings.Contains(resColor, "Cipher:") {
			t.Errorf("expected TCP Connected and TLS Handshake Cipher info, got:\n%s", resColor)
		}

		// --h1 --ping should emit an informational note that --ping is ignored for HTTP/1.1
		cmdH1Ping := exec.Command(binPath, "--h1", "--ping", srv.H1Addr+"/index.html")
		var outH1Ping bytes.Buffer
		cmdH1Ping.Stdout = &outH1Ping
		cmdH1Ping.Stderr = &outH1Ping
		if err := cmdH1Ping.Run(); err != nil {
			t.Fatalf("httpviz --h1 --ping failed: %v, out: %s", err, outH1Ping.String())
		}
		if !strings.Contains(outH1Ping.String(), "--ping is only supported on HTTP/2") {
			t.Errorf("expected --ping note on HTTP/1.1, got:\n%s", outH1Ping.String())
		}
	})

	// 14. Test -r / --read with HAR and PCAP files (Tree, Timeline, Body, and Validation)
	t.Run("ReadCaptureFiles_HAR_And_PCAP", func(t *testing.T) {
		tmpDir := t.TempDir()
		harFile := filepath.Join(tmpDir, "trace.har")
		harContent := `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "startedDateTime": "2026-10-16T12:00:00.000Z",
        "time": 35.0,
        "serverIPAddress": "93.184.215.14",
        "_securityDetails": {"protocol": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256"},
        "request": {
          "method": "GET",
          "url": "https://example.com/index.html",
          "httpVersion": "h2",
          "headers": [{"name": "user-agent", "value": "httpviz-har-test"}],
          "headersSize": 32
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "h2",
          "headers": [{"name": "content-type", "value": "text/html"}],
          "headersSize": 28,
          "bodySize": 18,
          "content": {"size": 18, "mimeType": "text/html", "text": "<h1>Hello HAR</h1>"}
        },
        "timings": {"dns": 2.0, "connect": 15.0, "ssl": 9.0, "send": 1.0, "wait": 12.0, "receive": 5.0}
      },
      {
        "startedDateTime": "2026-10-16T12:00:00.016Z",
        "time": 20.0,
        "serverIPAddress": "93.184.215.14",
        "request": {
          "method": "GET",
          "url": "https://example.com/style.css",
          "httpVersion": "h2",
          "headers": [{"name": "user-agent", "value": "httpviz-har-test"}],
          "headersSize": 30
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "h2",
          "headers": [{"name": "content-type", "value": "text/css"}],
          "headersSize": 26,
          "bodySize": 12,
          "content": {"size": 12, "mimeType": "text/css", "text": "body{margin:0}"}
        },
        "timings": {"dns": -1, "connect": -1, "ssl": -1, "send": 1.0, "wait": 14.0, "receive": 5.0}
      }
    ]
  }
}`
		if err := os.WriteFile(harFile, []byte(harContent), 0600); err != nil {
			t.Fatalf("failed to write HAR file: %v", err)
		}

		// Tree view with --body on HAR
		cmdHARTree := exec.Command(binPath, "-r", harFile, "--body")
		var outHARTree bytes.Buffer
		cmdHARTree.Stdout = &outHARTree
		cmdHARTree.Stderr = &outHARTree
		if err := cmdHARTree.Run(); err != nil {
			t.Fatalf("httpviz -r trace.har --body failed: %v, out: %s", err, outHARTree.String())
		}
		resHARTree := outHARTree.String()
		if !strings.Contains(resHARTree, "* DNS Lookup: example.com -> 93.184.215.14") ||
			!strings.Contains(resHARTree, "* TLS Handshake: TLSv1.3, Cipher: TLS_AES_128_GCM_SHA256") ||
			!strings.Contains(resHARTree, "Payload: <h1>Hello HAR</h1>") {
			t.Errorf("unexpected HAR tree output:\n%s", resHARTree)
		}

		// Timeline view on HAR
		cmdHARTimeline := exec.Command(binPath, "-r", harFile, "--timeline")
		var outHARTimeline bytes.Buffer
		cmdHARTimeline.Stdout = &outHARTimeline
		cmdHARTimeline.Stderr = &outHARTimeline
		if err := cmdHARTimeline.Run(); err != nil {
			t.Fatalf("httpviz -r trace.har --timeline failed: %v, out: %s", err, outHARTimeline.String())
		}
		resHARTimeline := outHARTimeline.String()
		if !strings.Contains(resHARTimeline, "Stream 1") || !strings.Contains(resHARTimeline, "Stream 3") {
			t.Errorf("expected Stream 1 and Stream 3 in HAR timeline output, got:\n%s", resHARTimeline)
		}

		// PCAP file test (HTTP/1.1 request & response)
		pcapFile := filepath.Join(tmpDir, "capture.pcap")
		pcapBytes := buildSimpleTestPCAP(
			[]byte("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello-pcap"),
		)
		if err := os.WriteFile(pcapFile, pcapBytes, 0600); err != nil {
			t.Fatalf("failed to write PCAP file: %v", err)
		}

		cmdPCAP := exec.Command(binPath, "-r", pcapFile, "--body")
		var outPCAP bytes.Buffer
		cmdPCAP.Stdout = &outPCAP
		cmdPCAP.Stderr = &outPCAP
		if err := cmdPCAP.Run(); err != nil {
			t.Fatalf("httpviz -r capture.pcap --body failed: %v, out: %s", err, outPCAP.String())
		}
		resPCAP := outPCAP.String()
		if !strings.Contains(resPCAP, "* Connected to 93.184.215.14:80") ||
			!strings.Contains(resPCAP, `"GET /hello HTTP/1.1"`) ||
			!strings.Contains(resPCAP, "Payload: hello-pcap") {
			t.Errorf("unexpected PCAP output:\n%s", resPCAP)
		}

		// Mutual exclusion: -r with URL argument should fail
		cmdConflictURL := exec.Command(binPath, "-r", harFile, srv.H1Addr)
		if err := cmdConflictURL.Run(); err == nil {
			t.Errorf("expected error when specifying both -r and URL argument")
		}

		// Mutual exclusion: -r with live-request flag (-X POST) should fail
		cmdConflictFlag := exec.Command(binPath, "-r", harFile, "-X", "POST")
		if err := cmdConflictFlag.Run(); err == nil {
			t.Errorf("expected error when specifying -r with -X POST")
		}
	})
}

func buildSimpleTestPCAP(reqPayload, respPayload []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1)) // Ethernet

	writePkt := func(usec uint32, srcIP string, srcPort uint16, dstIP string, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
		var pkt bytes.Buffer
		pkt.Write(make([]byte, 12))
		_ = binary.Write(&pkt, binary.BigEndian, uint16(0x0800))

		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(40+len(payload)))
		ip[8] = 64
		ip[9] = 6
		copy(ip[12:16], net.ParseIP(srcIP).To4())
		copy(ip[16:20], net.ParseIP(dstIP).To4())
		pkt.Write(ip)

		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:2], srcPort)
		binary.BigEndian.PutUint16(tcp[2:4], dstPort)
		binary.BigEndian.PutUint32(tcp[4:8], seq)
		binary.BigEndian.PutUint32(tcp[8:12], ack)
		tcp[12] = 5 << 4
		tcp[13] = flags
		binary.BigEndian.PutUint16(tcp[14:16], 65535)
		pkt.Write(tcp)
		pkt.Write(payload)

		raw := pkt.Bytes()
		_ = binary.Write(&buf, binary.LittleEndian, uint32(1700000000))
		_ = binary.Write(&buf, binary.LittleEndian, usec)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(raw)))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(raw)))
		buf.Write(raw)
	}

	writePkt(0, "10.0.0.1", 55000, "93.184.215.14", 80, 100, 0, 0x02, nil)
	writePkt(4000, "93.184.215.14", 80, "10.0.0.1", 55000, 200, 101, 0x12, nil)
	writePkt(8000, "10.0.0.1", 55000, "93.184.215.14", 80, 101, 201, 0x10, nil)
	writePkt(10000, "10.0.0.1", 55000, "93.184.215.14", 80, 101, 201, 0x10, reqPayload)
	writePkt(20000, "93.184.215.14", 80, "10.0.0.1", 55000, 201, 101+uint32(len(reqPayload)), 0x10, respPayload)

	return buf.Bytes()
}
