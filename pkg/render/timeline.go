package render

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/haccht/httpviz/pkg/event"
)

type streamSummary struct {
	status   string
	dataSize int
}

type gridCell struct {
	ch    rune
	color string
}

func getEventSymbol(e event.FrameEvent) string {
	isSend := (e.Direction == event.DirSend)
	isEnd := false
	for _, fn := range e.FlagNames {
		if fn == "END_STREAM" || fn == "ACK" {
			isEnd = true
			break
		}
	}
	if (e.Flags&0x1) != 0 && (e.FrameType == event.FrameSettings || e.FrameType == event.FramePing || e.FrameType == event.FrameData) {
		isEnd = true
	}

	var base byte
	switch e.FrameType {
	case event.FrameSettings:
		base = 'S'
	case event.FrameWindowUpdate:
		base = 'W'
	case event.FrameHeaders, event.FrameRequestLine, event.FrameStatusLine:
		base = 'H'
	case event.FrameData, event.FrameChunk:
		base = 'D'
	case event.FrameGoAway:
		base = 'G'
	case event.FramePing:
		base = 'P'
	case event.FrameRSTStream:
		base = 'R'
	default:
		base = 'F'
	}

	if !isSend {
		base = base + ('a' - 'A') // convert to lowercase
	}

	if isEnd {
		return fmt.Sprintf("[%c*]", base)
	}
	return fmt.Sprintf("[%c]", base)
}

// FormatTimeline formats events into an ASCII timeline chart using the current color setting.
func FormatTimeline(events []event.FrameEvent) string {
	return FormatTimelineColored(events, ColorEnabled())
}

// FormatTimelineColored formats events into an ASCII timeline chart with optional ANSI colors.
func FormatTimelineColored(events []event.FrameEvent, color bool) string {
	if len(events) == 0 {
		return "No events to display in timeline.\n"
	}

	// Group events by stream
	streamEvents := make(map[uint32][]event.FrameEvent)
	summaries := make(map[uint32]*streamSummary)
	var maxTime time.Duration

	for _, e := range events {
		if e.Timestamp > maxTime {
			maxTime = e.Timestamp
		}
		streamEvents[e.StreamID] = append(streamEvents[e.StreamID], e)

		if summaries[e.StreamID] == nil {
			summaries[e.StreamID] = &streamSummary{}
		}

		if e.FrameType == event.FrameHeaders || e.FrameType == event.FrameStatusLine {
			for _, h := range e.Headers {
				if h.Name == ":status" {
					status := h.Value
					if status == "200" {
						status = "200 OK"
					}
					summaries[e.StreamID].status = status
				}
			}
			if len(e.Details) > 0 && e.FrameType == event.FrameStatusLine {
				parts := strings.Split(e.Details[0], " ")
				if len(parts) >= 3 {
					summaries[e.StreamID].status = strings.Join(parts[1:], " ")
				}
			}
		} else if e.FrameType == event.FrameData || e.FrameType == event.FrameChunk {
			summaries[e.StreamID].dataSize += e.Length
		}
	}

	// Sort stream IDs
	var streamIDs []uint32
	for sid := range streamEvents {
		streamIDs = append(streamIDs, sid)
	}
	sort.Slice(streamIDs, func(i, j int) bool {
		return streamIDs[i] < streamIDs[j]
	})

	// Timeline grid setup
	chartWidth := 60
	maxMs := int(maxTime.Milliseconds())
	if maxMs < 60 {
		maxMs = 60
	}
	// Round up maxMs to nice multiple of 60
	stepMs := (maxMs + 5) / 6
	if stepMs < 10 {
		stepMs = 10
	}
	totalMs := stepMs * 6

	var sb strings.Builder

	// Header: Time (ms)
	sb.WriteString("Time (ms) ")
	sb.WriteString(wrapANSI("│", ansiDim, color))
	sb.WriteString(" ")
	for i := 0; i <= 6; i++ {
		tVal := fmt.Sprintf("%-10d", i*stepMs)
		if i == 6 {
			tVal = fmt.Sprintf("%d", i*stepMs)
		}
		sb.WriteString(tVal)
	}
	sb.WriteString("\n")

	topBorder := "──────────┼" + strings.Repeat("─", chartWidth+3)
	sb.WriteString(wrapANSI(topBorder, ansiDim, color) + "\n")

	for _, sid := range streamIDs {
		evs := streamEvents[sid]
		cells := make([]gridCell, chartWidth+3)
		for i := range cells {
			cells[i] = gridCell{ch: ' '}
		}

		// Calculate start and end indices
		firstMs := int(evs[0].Timestamp.Milliseconds())
		lastMs := int(evs[len(evs)-1].Timestamp.Milliseconds())
		firstCol := (firstMs * chartWidth) / totalMs
		lastCol := (lastMs * chartWidth) / totalMs
		if lastCol >= len(cells) {
			lastCol = len(cells) - 1
		}

		for c := firstCol; c <= lastCol; c++ {
			cells[c] = gridCell{ch: '─', color: ansiDim}
		}

		colCursor := 0
		for _, e := range evs {
			targetCol := (int(e.Timestamp.Milliseconds()) * chartWidth) / totalMs
			if targetCol < colCursor {
				targetCol = colCursor
			}
			sym := getEventSymbol(e)
			symRunes := []rune(sym)
			symColor := frameTypeColorCode(e.FrameType)

			for i, r := range symRunes {
				idx := targetCol + i
				cell := gridCell{ch: r, color: symColor}
				if idx < len(cells) {
					cells[idx] = cell
				} else {
					cells = append(cells, cell)
				}
			}
			colCursor = targetCol + len(symRunes)
		}

		// Trim trailing spaces
		endIdx := len(cells)
		for endIdx > 0 && cells[endIdx-1].ch == ' ' {
			endIdx--
		}
		rowContent := renderCells(cells[:endIdx], color)

		summaryStr := ""
		sum := summaries[sid]
		if sum != nil && sum.status != "" {
			styledStatus := wrapANSI(sum.status, statusColorCode(sum.status), color)
			sizeStr := ""
			if sum.dataSize >= 1024 {
				sizeStr = fmt.Sprintf("%.1fKB", float64(sum.dataSize)/1024.0)
			} else if sum.dataSize > 0 {
				sizeStr = fmt.Sprintf("%dB", sum.dataSize)
			}
			if sizeStr != "" {
				summaryStr = fmt.Sprintf(" (%s, %s)", styledStatus, sizeStr)
			} else {
				summaryStr = fmt.Sprintf(" (%s)", styledStatus)
			}
		}

		streamLabel := wrapANSI(fmt.Sprintf("Stream %-3d", sid), streamColorCode(sid), color)
		sep := wrapANSI("│", ansiDim, color)
		sb.WriteString(fmt.Sprintf("%s%s %s%s\n", streamLabel, sep, rowContent, summaryStr))
	}

	bottomBorder := "──────────┴" + strings.Repeat("─", chartWidth+3)
	sb.WriteString(wrapANSI(bottomBorder, ansiDim, color) + "\n")
	sb.WriteString("Legend:\n")
	sb.WriteString("  Upper = Sent (Client -> Server), Lower = Recv (Server -> Client)\n")
	sb.WriteString("  [S]/[s] SETTINGS   [W]/[w] WINDOW_UPDATE   [H]/[h] HEADERS\n")
	sb.WriteString("  [D]/[d] DATA       [G]/[g] GOAWAY          * = END_STREAM / ACK\n")

	return sb.String()
}

func renderCells(cells []gridCell, color bool) string {
	var sb strings.Builder
	for _, c := range cells {
		if color && c.color != "" {
			sb.WriteString(c.color)
			sb.WriteRune(c.ch)
			sb.WriteString(ansiReset)
		} else {
			sb.WriteRune(c.ch)
		}
	}
	return sb.String()
}

// RenderTimeline writes the formatted timeline ASCII chart to w.
func RenderTimeline(w io.Writer, events []event.FrameEvent) {
	_, _ = fmt.Fprint(w, FormatTimeline(events))
}
