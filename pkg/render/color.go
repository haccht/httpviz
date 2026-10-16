package render

import (
	"os"
	"strings"
	"sync/atomic"

	"github.com/haccht/httpviz/pkg/event"
)

const (
	ansiReset       = "\x1b[0m"
	ansiDim         = "\x1b[2m"
	ansiRed         = "\x1b[31m"
	ansiGreen       = "\x1b[32m"
	ansiYellow      = "\x1b[33m"
	ansiBlue        = "\x1b[34m"
	ansiMagenta     = "\x1b[35m"
	ansiCyan        = "\x1b[36m"
	ansiBoldRed     = "\x1b[1;31m"
	ansiBoldGreen   = "\x1b[1;32m"
	ansiBoldYellow  = "\x1b[1;33m"
	ansiBoldBlue    = "\x1b[1;34m"
	ansiBoldMagenta = "\x1b[1;35m"
	ansiBoldCyan    = "\x1b[1;36m"
)

var streamPalette = []string{
	ansiCyan,
	ansiYellow,
	ansiMagenta,
	ansiGreen,
	ansiBlue,
}

var globalColorEnabled atomic.Bool

// SetColorEnabled sets the default colorization state for FormatInfo, FormatEvent, and FormatTimeline.
func SetColorEnabled(enabled bool) {
	globalColorEnabled.Store(enabled)
}

// ColorEnabled returns whether default colorization is currently enabled.
func ColorEnabled() bool {
	return globalColorEnabled.Load()
}

// ResolveColorMode determines whether ANSI colors should be enabled based on the --color flag ("auto", "always", "never"),
// environment variables (NO_COLOR, TERM), and whether outFile is a terminal character device.
func ResolveColorMode(mode string, outFile *os.File) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always", "true", "1", "yes":
		return true
	case "never", "false", "0", "no":
		return false
	default: // "auto"
		if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
			return false
		}
		if outFile == nil {
			return false
		}
		fi, err := outFile.Stat()
		if err != nil {
			return false
		}
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
}

func wrapANSI(text, code string, enabled bool) string {
	if !enabled || code == "" || text == "" {
		return text
	}
	return code + text + ansiReset
}

func streamColorCode(streamID uint32) string {
	if streamID == 0 {
		return ansiDim
	}
	idx := int(streamID/2) % len(streamPalette)
	if idx < 0 {
		idx = 0
	}
	return streamPalette[idx]
}

func directionColorCode(dir event.Direction) string {
	switch dir {
	case event.DirSend:
		return ansiBoldCyan
	case event.DirRecv:
		return ansiBoldGreen
	default:
		return ansiDim
	}
}

func frameTypeColorCode(frameType string) string {
	switch frameType {
	case event.FrameHeaders, event.FrameRequestLine, event.FrameStatusLine:
		return ansiBoldBlue
	case event.FrameData, event.FrameChunk, event.FrameStream:
		return ansiGreen
	case event.FrameSettings, event.FrameWindowUpdate, event.FramePing, event.FrameMagic, event.FrameMaxData, event.FrameMaxStreamData:
		return ansiYellow
	case event.FrameRSTStream, event.FrameGoAway, event.FrameConnectionClose, event.FrameResetStream:
		return ansiBoldRed
	case event.FrameQUICPacket:
		return ansiBoldMagenta
	default:
		return ansiCyan
	}
}

func statusColorCode(statusVal string) string {
	trimmed := strings.TrimSpace(statusVal)
	if strings.HasPrefix(trimmed, "HTTP/") {
		parts := strings.SplitN(trimmed, " ", 3)
		if len(parts) >= 2 {
			trimmed = parts[1]
		}
	}
	switch {
	case strings.HasPrefix(trimmed, "2"):
		return ansiBoldGreen
	case strings.HasPrefix(trimmed, "3"):
		return ansiBoldYellow
	case strings.HasPrefix(trimmed, "4"), strings.HasPrefix(trimmed, "5"):
		return ansiBoldRed
	default:
		return ansiCyan
	}
}
