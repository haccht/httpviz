package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/haccht/httpviz/pkg/event"
)

func TestTimelineRenderer(t *testing.T) {
	events := []event.FrameEvent{
		{
			Timestamp: 0 * time.Millisecond,
			Direction: event.DirSend,
			StreamID:  0,
			FrameType: event.FrameSettings,
		},
		{
			Timestamp: 5 * time.Millisecond,
			Direction: event.DirSend,
			StreamID:  1,
			FrameType: event.FrameHeaders,
		},
		{
			Timestamp: 6 * time.Millisecond,
			Direction: event.DirSend,
			StreamID:  3,
			FrameType: event.FrameHeaders,
		},
		{
			Timestamp: 20 * time.Millisecond,
			Direction: event.DirRecv,
			StreamID:  1,
			FrameType: event.FrameHeaders,
			Headers:   []event.HeaderField{{Name: ":status", Value: "200"}},
		},
		{
			Timestamp: 22 * time.Millisecond,
			Direction: event.DirRecv,
			StreamID:  1,
			FrameType: event.FrameData,
			Length:    1228,
			FlagNames: []string{"END_STREAM"},
		},
		{
			Timestamp: 25 * time.Millisecond,
			Direction: event.DirRecv,
			StreamID:  3,
			FrameType: event.FrameHeaders,
			Headers:   []event.HeaderField{{Name: ":status", Value: "200"}},
		},
		{
			Timestamp: 30 * time.Millisecond,
			Direction: event.DirRecv,
			StreamID:  3,
			FrameType: event.FrameData,
			Length:    4608,
			FlagNames: []string{"END_STREAM"},
		},
	}

	var buf bytes.Buffer
	RenderTimeline(&buf, events)
	output := buf.String()

	t.Logf("Timeline output:\n%s", output)

	if !strings.Contains(output, "Stream 0") {
		t.Errorf("expected Stream 0 row")
	}
	if !strings.Contains(output, "Stream 1") {
		t.Errorf("expected Stream 1 row")
	}
	if !strings.Contains(output, "Stream 3") {
		t.Errorf("expected Stream 3 row")
	}
	if !strings.Contains(output, "1.2KB") {
		t.Errorf("expected Stream 1 size 1.2KB")
	}
	if !strings.Contains(output, "4.5KB") {
		t.Errorf("expected Stream 3 size 4.5KB")
	}
	if !strings.Contains(output, "Legend:") {
		t.Errorf("expected Legend")
	}

	// Verify colored timeline contains ANSI codes and has identical column alignment when stripped
	colored := FormatTimelineColored(events, true)
	if !strings.Contains(colored, "\x1b[") {
		t.Errorf("expected ANSI escape sequence in colored timeline output")
	}
	if stripped := stripANSI(colored); stripped != output {
		t.Errorf("stripped colored timeline does not match plain timeline:\ngot:\n%s\nwant:\n%s", stripped, output)
	}
}
