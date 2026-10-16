package render

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/haccht/httpviz/pkg/event"
)

func isPrintableText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func truncateUTF8(b []byte, limit int) []byte {
	if limit <= 0 || len(b) <= limit {
		return b
	}
	res := b[:limit]
	for len(res) > 0 && !utf8.Valid(res) {
		res = res[:len(res)-1]
	}
	if len(res) == 0 {
		return b[:limit]
	}
	return res
}

// FormatInfo formats an informational connection message using the current color setting.
func FormatInfo(msg string, elapsed time.Duration) string {
	return FormatInfoColored(msg, elapsed, ColorEnabled())
}

// FormatInfoColored formats an informational connection message with optional ANSI colors.
func FormatInfoColored(msg string, elapsed time.Duration, color bool) string {
	ts := wrapANSI(fmt.Sprintf("[%6.3fs]", elapsed.Seconds()), ansiDim, color)
	styledMsg := wrapANSI(msg, ansiDim, color)
	return fmt.Sprintf("%s %s\n", ts, styledMsg)
}

// FormatEvent formats a single FrameEvent into its tree representation using the current color setting.
func FormatEvent(e event.FrameEvent) string {
	return FormatEventColored(e, ColorEnabled())
}

// FormatEventColored formats a single FrameEvent into its tree representation with optional ANSI colors.
func FormatEventColored(e event.FrameEvent, color bool) string {
	var sb strings.Builder
	tsStr := wrapANSI(fmt.Sprintf("[%6.3fs]", e.Timestamp.Seconds()), ansiDim, color)
	rawDir := string(e.Direction)
	if rawDir == "" {
		rawDir = "───"
	}
	dirStr := wrapANSI(rawDir, directionColorCode(e.Direction), color)

	streamStr := ""
	if e.FrameType != event.FrameRequestLine && e.FrameType != event.FrameStatusLine && e.FrameType != event.FrameChunk && e.FrameType != event.FrameMagic {
		streamStr = wrapANSI(fmt.Sprintf("[Stream %d]", e.StreamID), streamColorCode(e.StreamID), color) + " "
	}

	headerPart := wrapANSI(fmt.Sprintf("%-16s", e.FrameType), frameTypeColorCode(e.FrameType), color)

	var metaParts []string
	if e.Length > 0 || (e.Length == 0 && (e.FrameType == event.FrameSettings || e.FrameType == event.FrameHeaders || e.FrameType == event.FrameData)) {
		metaParts = append(metaParts, fmt.Sprintf("len=%d", e.Length))
	}
	if len(e.FlagNames) > 0 {
		metaParts = append(metaParts, fmt.Sprintf("flags=0x%x [%s]", e.Flags, strings.Join(e.FlagNames, " | ")))
	} else if e.Flags > 0 {
		metaParts = append(metaParts, fmt.Sprintf("flags=0x%x", e.Flags))
	}

	metaStr := ""
	if len(metaParts) > 0 {
		metaStr = wrapANSI(fmt.Sprintf("(%s)", strings.Join(metaParts, ", ")), ansiDim, color)
	}

	// First line
	switch e.FrameType {
	case event.FrameMagic:
		detail := ""
		if len(e.Details) > 0 {
			detail = " " + e.Details[0]
		}
		magicPart := wrapANSI(fmt.Sprintf("%-9s", e.FrameType), frameTypeColorCode(e.FrameType), color)
		lenPart := wrapANSI("(24B)", ansiDim, color)
		sb.WriteString(fmt.Sprintf("%s %s %s %s%s\n", tsStr, dirStr, magicPart, lenPart, detail))
	case event.FrameRequestLine, event.FrameStatusLine:
		detail := ""
		if len(e.Details) > 0 {
			quoted := fmt.Sprintf("%q", e.Details[0])
			if e.FrameType == event.FrameStatusLine {
				quoted = wrapANSI(quoted, statusColorCode(e.Details[0]), color)
			}
			detail = quoted
		}
		sb.WriteString(fmt.Sprintf("%s %s %s %s\n", tsStr, dirStr, headerPart, detail))
	case event.FrameChunk, event.FrameQUICPacket:
		detail := ""
		if len(e.Details) > 0 {
			detail = wrapANSI(fmt.Sprintf("(%s)", strings.Join(e.Details, ", ")), ansiDim, color)
		}
		sb.WriteString(fmt.Sprintf("%s %s %s %s\n", tsStr, dirStr, headerPart, detail))
	default:
		if metaStr != "" {
			sb.WriteString(fmt.Sprintf("%s %s %s%s %s\n", tsStr, dirStr, streamStr, headerPart, metaStr))
		} else {
			sb.WriteString(fmt.Sprintf("%s %s %s%s\n", tsStr, dirStr, streamStr, headerPart))
		}
	}

	indent := "             "
	pipeBar := wrapANSI("│  ", ansiDim, color)

	// HPACK or QPACK compression info line
	if e.RawHeaderSize > 0 && e.CompHeaderSize > 0 {
		ratio := (e.CompHeaderSize * 100) / e.RawHeaderSize
		hpackInfo := wrapANSI(
			fmt.Sprintf("(HPACK: Compressed %dB -> Decompressed %dB, Ratio: %d%%)", e.CompHeaderSize, e.RawHeaderSize, ratio),
			ansiDim,
			color,
		)
		sb.WriteString(fmt.Sprintf("%s%s%s\n", indent, pipeBar, hpackInfo))
	}

	// Prepare tree child lines
	var childLines []string

	for _, h := range e.Headers {
		val := h.Value
		if h.Name == ":status" {
			val = wrapANSI(val, statusColorCode(val), color)
		}
		line := fmt.Sprintf("%s: %s", h.Name, val)
		if h.IndexInfo != "" {
			line += "  " + wrapANSI(fmt.Sprintf("[%s]", h.IndexInfo), ansiDim, color)
		}
		childLines = append(childLines, line)
	}

	if e.FrameType != event.FrameRequestLine && e.FrameType != event.FrameStatusLine && e.FrameType != event.FrameChunk && e.FrameType != event.FrameMagic && e.FrameType != event.FrameQUICPacket {
		for _, d := range e.Details {
			childLines = append(childLines, d)
		}
	}

	// Window transitions
	if e.ConnWindowBefore != 0 || e.ConnWindowAfter != 0 || e.StreamWindowBefore != 0 || e.StreamWindowAfter != 0 {
		var winParts []string
		if e.ConnWindowBefore != 0 || e.ConnWindowAfter != 0 {
			winParts = append(winParts, fmt.Sprintf("[Conn Window: %d -> %d]", e.ConnWindowBefore, e.ConnWindowAfter))
		}
		if e.StreamID > 0 && (e.StreamWindowBefore != 0 || e.StreamWindowAfter != 0) {
			winParts = append(winParts, fmt.Sprintf("[Stream %d Window: %d -> %d]", e.StreamID, e.StreamWindowBefore, e.StreamWindowAfter))
		}
		if len(winParts) > 0 {
			childLines = append(childLines, wrapANSI(strings.Join(winParts, " "), ansiYellow, color))
		}
	}

	// Render child items
	for i, line := range childLines {
		rawPrefix := "├─ "
		if i == len(childLines)-1 && len(e.Payload) == 0 && len(e.SubEvents) == 0 {
			rawPrefix = "└─ "
		}
		prefix := wrapANSI(rawPrefix, ansiDim, color)
		sb.WriteString(fmt.Sprintf("%s%s%s\n", indent, prefix, line))
	}

	// Render payload if present
	if len(e.Payload) > 0 {
		rawPrefix := "└─ "
		bodyIndent := indent + "   "
		if len(e.SubEvents) > 0 {
			rawPrefix = "├─ "
			bodyIndent = indent + pipeBar
		}
		prefix := wrapANSI(rawPrefix, ansiDim, color)
		totalLen := len(e.Payload)
		if !isPrintableText(e.Payload) {
			sb.WriteString(fmt.Sprintf("%s%sPayload: <binary %dB>\n", indent, prefix, totalLen))
		} else {
			displayPayload := e.Payload
			truncated := false
			if e.PayloadLimit > 0 && totalLen > e.PayloadLimit {
				displayPayload = truncateUTF8(e.Payload, e.PayloadLimit)
				truncated = true
			}
			normalized := strings.ReplaceAll(string(displayPayload), "\r\n", "\n")
			trimmed := strings.TrimRight(normalized, "\n")
			lines := strings.Split(trimmed, "\n")
			if truncated {
				if len(lines) <= 1 {
					sb.WriteString(fmt.Sprintf("%s%sPayload (%d/%dB): %s ... (truncated)\n", indent, prefix, len(displayPayload), totalLen, trimmed))
				} else {
					sb.WriteString(fmt.Sprintf("%s%sPayload (%d/%dB):\n", indent, prefix, len(displayPayload), totalLen))
					for i, l := range lines {
						if i == len(lines)-1 {
							sb.WriteString(fmt.Sprintf("%s%s ... (truncated)\n", bodyIndent, l))
						} else {
							sb.WriteString(fmt.Sprintf("%s%s\n", bodyIndent, l))
						}
					}
				}
			} else {
				if len(lines) <= 1 {
					sb.WriteString(fmt.Sprintf("%s%sPayload: %s\n", indent, prefix, trimmed))
				} else {
					sb.WriteString(fmt.Sprintf("%s%sPayload:\n", indent, prefix))
					for _, l := range lines {
						sb.WriteString(fmt.Sprintf("%s%s\n", bodyIndent, l))
					}
				}
			}
		}
	}

	// Render sub-events (e.g. frames inside QUIC packets)
	for i, sub := range e.SubEvents {
		isLast := (i == len(e.SubEvents)-1)
		subStr := formatSubEvent(sub, indent, isLast, color)
		sb.WriteString(subStr)
	}

	return sb.String()
}

func formatSubEvent(e event.FrameEvent, parentIndent string, isLast bool, color bool) string {
	var sb strings.Builder
	rawPrefix := "├─ "
	childIndent := parentIndent + wrapANSI("│  ", ansiDim, color)
	if isLast {
		rawPrefix = "└─ "
		childIndent = parentIndent + "   "
	}
	prefix := wrapANSI(rawPrefix, ansiDim, color)

	streamStr := ""
	if e.StreamID > 0 {
		streamStr = wrapANSI(fmt.Sprintf("[Stream %d]", e.StreamID), streamColorCode(e.StreamID), color) + " "
	}

	var metaParts []string
	if e.Length > 0 {
		metaParts = append(metaParts, fmt.Sprintf("len=%d", e.Length))
	}
	if len(e.FlagNames) > 0 {
		metaParts = append(metaParts, fmt.Sprintf("flags=0x%x [%s]", e.Flags, strings.Join(e.FlagNames, " | ")))
	}
	metaStr := ""
	if len(metaParts) > 0 {
		metaStr = " " + wrapANSI(fmt.Sprintf("(%s)", strings.Join(metaParts, ", ")), ansiDim, color)
	}

	ftStr := wrapANSI(e.FrameType, frameTypeColorCode(e.FrameType), color)
	sb.WriteString(fmt.Sprintf("%s%s%s%s%s\n", parentIndent, prefix, streamStr, ftStr, metaStr))

	var childLines []string
	for _, h := range e.Headers {
		line := fmt.Sprintf("%s: %s", h.Name, h.Value)
		if h.IndexInfo != "" {
			line += "  " + wrapANSI(fmt.Sprintf("[%s]", h.IndexInfo), ansiDim, color)
		}
		childLines = append(childLines, line)
	}
	for _, d := range e.Details {
		childLines = append(childLines, d)
	}

	for i, line := range childLines {
		p := "├─ "
		if i == len(childLines)-1 {
			p = "└─ "
		}
		sb.WriteString(fmt.Sprintf("%s%s%s\n", childIndent, wrapANSI(p, ansiDim, color), line))
	}

	return sb.String()
}

// RenderTree renders a list of events to the specified writer.
func RenderTree(w io.Writer, events []event.FrameEvent) {
	for _, e := range events {
		_, _ = fmt.Fprint(w, FormatEvent(e))
	}
}
