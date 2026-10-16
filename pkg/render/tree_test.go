package render

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/haccht/httpviz/pkg/event"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

func TestTreeRenderer(t *testing.T) {
	events := []event.FrameEvent{
		{
			Timestamp: 1 * time.Millisecond,
			Direction: event.DirSend,
			FrameType: event.FrameMagic,
			Length:    24,
			Details:   []string{`"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`},
		},
		{
			Timestamp: 1 * time.Millisecond,
			Direction: event.DirSend,
			StreamID:  0,
			FrameType: event.FrameSettings,
			Length:    18,
			Flags:     0x0,
			Details: []string{
				"ENABLE_PUSH: 0",
				"INITIAL_WINDOW_SIZE: 4194304 (4MB)",
			},
		},
		{
			Timestamp: 2 * time.Millisecond,
			Direction: event.DirSend,
			StreamID:  1,
			FrameType: event.FrameHeaders,
			Length:    31,
			Flags:     0x5,
			FlagNames: []string{"END_HEADERS", "END_STREAM"},
			Headers: []event.HeaderField{
				{Name: ":method", Value: "GET", IndexInfo: "Static Index: 2"},
				{Name: ":path", Value: "/index.html", IndexInfo: "Literal, Indexed -> Dynamic Index: 62"},
			},
			RawHeaderSize:  118,
			CompHeaderSize: 31,
		},
		{
			Timestamp:          25 * time.Millisecond,
			Direction:          event.DirRecv,
			StreamID:           1,
			FrameType:          event.FrameData,
			Length:             1000,
			Flags:              0x0,
			ConnWindowBefore:   65535,
			ConnWindowAfter:    64535,
			StreamWindowBefore: 4194304,
			StreamWindowAfter:  4193304,
		},
	}

	var buf bytes.Buffer
	RenderTree(&buf, events)
	output := buf.String()

	t.Logf("Tree output:\n%s", output)

	if !strings.Contains(output, "MAGIC") {
		t.Errorf("expected MAGIC in output")
	}
	if !strings.Contains(output, "SETTINGS") {
		t.Errorf("expected SETTINGS in output")
	}
	if !strings.Contains(output, "HPACK: Compressed 31B -> Decompressed 118B") {
		t.Errorf("expected HPACK compression ratio info in output")
	}
	if !strings.Contains(output, "[Conn Window: 65535 -> 64535]") {
		t.Errorf("expected Conn Window transition in output")
	}
	if !strings.Contains(output, "[Stream 1 Window: 4194304 -> 4193304]") {
		t.Errorf("expected Stream 1 Window transition in output")
	}

	// Verify colored output contains ANSI codes and matches plain output when stripped
	for _, ev := range events {
		plain := FormatEventColored(ev, false)
		colored := FormatEventColored(ev, true)
		if !strings.Contains(colored, "\x1b[") {
			t.Errorf("expected ANSI escape sequence in colored output for %s", ev.FrameType)
		}
		if stripped := stripANSI(colored); stripped != plain {
			t.Errorf("stripped colored output does not match plain output:\ngot:\n%s\nwant:\n%s", stripped, plain)
		}
	}
}

func TestResolveColorMode(t *testing.T) {
	if !ResolveColorMode("always", nil) {
		t.Errorf("expected ResolveColorMode('always', nil) to be true")
	}
	if ResolveColorMode("never", nil) {
		t.Errorf("expected ResolveColorMode('never', nil) to be false")
	}
	if ResolveColorMode("auto", nil) {
		t.Errorf("expected ResolveColorMode('auto', nil) to be false")
	}
}
