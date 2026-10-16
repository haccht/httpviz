package h2

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Options is an alias for event.Options.
type Options = event.Options

// Static table lookup for common HTTP/2 headers (RFC 7541 Appendix A).
var staticTable = map[string]struct {
	Index    int
	HasValue bool
	Value    string
}{
	":authority":                       {1, false, ""},
	":method:GET":                      {2, true, "GET"},
	":method:POST":                     {3, true, "POST"},
	":path:/":                          {4, true, "/"},
	":path:/index.html":                {5, true, "/index.html"},
	":scheme:http":                     {6, true, "http"},
	":scheme:https":                    {7, true, "https"},
	":status:200":                      {8, true, "200"},
	":status:204":                      {9, true, "204"},
	":status:206":                      {10, true, "206"},
	":status:304":                      {11, true, "304"},
	":status:400":                      {12, true, "400"},
	":status:404":                      {13, true, "404"},
	":status:500":                      {14, true, "500"},
	"accept-charset":                   {15, false, ""},
	"accept-encoding:gzip, deflate":    {16, true, "gzip, deflate"},
	"accept-language":                  {17, false, ""},
	"accept-ranges":                    {18, false, ""},
	"accept":                           {19, false, ""},
	"access-control-allow-origin":      {20, false, ""},
	"age":                              {21, false, ""},
	"allow":                            {22, false, ""},
	"authorization":                    {23, false, ""},
	"cache-control":                    {24, false, ""},
	"content-disposition":              {25, false, ""},
	"content-encoding":                 {26, false, ""},
	"content-language":                 {27, false, ""},
	"content-length":                   {28, false, ""},
	"content-location":                 {29, false, ""},
	"content-range":                    {30, false, ""},
	"content-type":                     {31, false, ""},
	"cookie":                           {32, false, ""},
	"date":                             {33, false, ""},
	"etag":                             {34, false, ""},
	"expect":                           {35, false, ""},
	"expires":                          {36, false, ""},
	"from":                             {37, false, ""},
	"host":                             {38, false, ""},
	"if-match":                         {39, false, ""},
	"if-modified-since":                {40, false, ""},
	"if-none-match":                    {41, false, ""},
	"if-range":                         {42, false, ""},
	"if-unmodified-since":              {43, false, ""},
	"last-modified":                    {44, false, ""},
	"link":                             {45, false, ""},
	"location":                         {46, false, ""},
	"max-forwards":                     {47, false, ""},
	"proxy-authenticate":               {48, false, ""},
	"proxy-authorization":              {49, false, ""},
	"range":                            {50, false, ""},
	"referer":                          {51, false, ""},
	"refresh":                          {52, false, ""},
	"retry-after":                      {53, false, ""},
	"server":                           {54, false, ""},
	"set-cookie":                       {55, false, ""},
	"strict-transport-security":        {56, false, ""},
	"transfer-encoding":                {57, false, ""},
	"user-agent":                       {58, false, ""},
	"vary":                             {59, false, ""},
	"via":                              {60, false, ""},
	"www-authenticate":                 {61, false, ""},
}

func getIndexInfo(name, value string, dynamicTable map[string]int, nextDynamicIndex *int) string {
	key := name + ":" + value
	if entry, ok := staticTable[key]; ok && entry.HasValue {
		return fmt.Sprintf("Static Index: %d", entry.Index)
	}
	if dynamicTable != nil {
		if idx, ok := dynamicTable[key]; ok {
			return fmt.Sprintf("Dynamic Index: %d", idx)
		}
		if nextDynamicIndex != nil && *nextDynamicIndex > 0 {
			idx := *nextDynamicIndex
			*nextDynamicIndex++
			dynamicTable[key] = idx
			return fmt.Sprintf("Literal, Indexed -> Dynamic Index: %d", idx)
		}
	}
	if entry, ok := staticTable[name]; ok {
		return fmt.Sprintf("Literal, Indexed (Name Index: %d)", entry.Index)
	}
	return "Literal, Indexed"
}

// Run executes HTTP/2 requests to the given URLs over a single multiplexed connection.
func Run(rawURLs []string, opts Options) ([]event.FrameEvent, error) {
	if len(rawURLs) == 0 {
		return nil, nil
	}

	timeout := opts.EffectiveTimeout()
	method := opts.ResolveMethod()
	rec := event.NewRecorder(opts)

	u0, err := url.Parse(rawURLs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURLs[0], err)
	}

	scheme, host, _ := event.NormalizeURL(u0, "https")

	connStart := time.Now()
	var conn net.Conn

	if opts.Conn != nil {
		conn = opts.Conn
		if !opts.ConnStart.IsZero() {
			connStart = opts.ConnStart
		}
	} else {
		if scheme == "http" {
			return nil, fmt.Errorf("HTTP/2 requires https:// scheme (got %q)", u0.Scheme)
		}
		dialedConn, _, dialStart, err := event.DialTCPOrTLS(u0, "https", host, []string{"h2"}, "h2", opts)
		if err != nil {
			return nil, err
		}
		conn = dialedConn
		connStart = dialStart
	}
	defer conn.Close()

	// Send Client Preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("failed to send client preface: %w", err)
	}
	rec.RecordEvent(event.FrameEvent{
		Timestamp: time.Since(connStart),
		Direction: event.DirSend,
		StreamID:  0,
		FrameType: event.FrameMagic,
		Length:    len(http2.ClientPreface),
		Details:   []string{`"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`},
	})

	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	// Flow control tracking
	connWindow := int64(65535)
	streamWindows := make(map[uint32]int64)
	sendConnWindow := int64(65535)
	sendStreamWindows := make(map[uint32]int64)

	// Send initial client SETTINGS
	initialWindowSize := opts.WindowSize
	if initialWindowSize == 0 {
		initialWindowSize = 4194304
	}
	settings := []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: initialWindowSize},
	}
	if err := framer.WriteSettings(settings...); err != nil {
		return nil, fmt.Errorf("failed to write settings: %w", err)
	}
	winSizeDetail := fmt.Sprintf("INITIAL_WINDOW_SIZE: %d", initialWindowSize)
	if initialWindowSize >= 1048576 && initialWindowSize%1048576 == 0 {
		winSizeDetail = fmt.Sprintf("INITIAL_WINDOW_SIZE: %d (%dMB)", initialWindowSize, initialWindowSize/1048576)
	}
	rec.RecordEvent(event.FrameEvent{
		Timestamp: time.Since(connStart),
		Direction: event.DirSend,
		StreamID:  0,
		FrameType: event.FrameSettings,
		Length:    len(settings) * 6,
		Flags:     0x0,
		Details: []string{
			"ENABLE_PUSH: 0",
			winSizeDetail,
		},
	})

	var pingPending bool
	var pingSentAt time.Time
	if opts.Ping {
		pingData := [8]byte{'h', 't', 't', 'p', 'v', 'i', 'z', '!'}
		if err := framer.WritePing(false, pingData); err != nil {
			return rec.Events(), fmt.Errorf("failed to write PING: %w", err)
		}
		pingPending = true
		pingSentAt = time.Now()
		rec.RecordEvent(event.FrameEvent{
			Timestamp: time.Since(connStart),
			Direction: event.DirSend,
			StreamID:  0,
			FrameType: event.FramePing,
			Length:    8,
			Flags:     0x0,
			Details:   []string{`opaque_data="httpviz!"`},
		})
	}

	activeStreams := make(map[uint32]bool)
	var hpackBuf bytes.Buffer
	encoder := hpack.NewEncoder(&hpackBuf)
	sendDynamicTable := make(map[string]int)
	sendDynamicIndex := 62
	recvDynamicTable := make(map[string]int)
	recvDynamicIndex := 62

	hasBody := len(opts.Data) > 0
	customHeaders := opts.ParseCustomHeaders()

	// Send HEADERS (and optional DATA) for each URL on odd stream IDs (1, 3, 5, ...)
	for idx, rawU := range rawURLs {
		u, err := url.Parse(rawU)
		if err != nil {
			return rec.Events(), fmt.Errorf("invalid URL %q: %w", rawU, err)
		}
		streamID := uint32(idx*2 + 1)
		activeStreams[streamID] = true
		streamWindows[streamID] = int64(initialWindowSize)
		sendStreamWindows[streamID] = 65535

		_, _, path := event.NormalizeURL(u, "https")

		hpackBuf.Reset()
		reqHeaders := []event.HeaderField{
			{Name: ":method", Value: method},
			{Name: ":path", Value: path},
			{Name: ":scheme", Value: u.Scheme},
			{Name: ":authority", Value: u.Host},
			{Name: "user-agent", Value: "httpviz/0.1.0"},
			{Name: "accept", Value: "*/*"},
		}

		setOrAppendHeader := func(name, val string) {
			lowerName := strings.ToLower(name)
			if lowerName == "host" || lowerName == ":authority" {
				reqHeaders[3].Value = val
				return
			}
			for idx := range reqHeaders {
				if reqHeaders[idx].Name == lowerName {
					reqHeaders[idx].Value = val
					return
				}
			}
			reqHeaders = append(reqHeaders, event.HeaderField{Name: lowerName, Value: val})
		}

		if hasBody {
			setOrAppendHeader("content-type", "application/x-www-form-urlencoded")
			setOrAppendHeader("content-length", strconv.Itoa(len(opts.Data)))
		}

		for _, h := range customHeaders {
			setOrAppendHeader(h.Name, h.Value)
		}

		rawHeaderBytes := 0
		for i := range reqHeaders {
			rawHeaderBytes += len(reqHeaders[i].Name) + len(reqHeaders[i].Value) + 32
			_ = encoder.WriteField(hpack.HeaderField{Name: reqHeaders[i].Name, Value: reqHeaders[i].Value})
			reqHeaders[i].IndexInfo = getIndexInfo(reqHeaders[i].Name, reqHeaders[i].Value, sendDynamicTable, &sendDynamicIndex)
		}

		compBytes := append([]byte(nil), hpackBuf.Bytes()...)
		err = framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: compBytes,
			EndStream:     !hasBody,
			EndHeaders:    true,
		})
		if err != nil {
			return rec.Events(), fmt.Errorf("failed to write headers for stream %d: %w", streamID, err)
		}

		hdrFlags := uint8(0x5)
		hdrFlagNames := []string{"END_HEADERS", "END_STREAM"}
		if hasBody {
			hdrFlags = 0x4
			hdrFlagNames = []string{"END_HEADERS"}
		}

		rec.RecordEvent(event.FrameEvent{
			Timestamp:      time.Since(connStart),
			Direction:      event.DirSend,
			StreamID:       streamID,
			FrameType:      event.FrameHeaders,
			Length:         len(compBytes),
			Flags:          hdrFlags,
			FlagNames:      hdrFlagNames,
			Headers:        reqHeaders,
			RawHeaderSize:  rawHeaderBytes,
			CompHeaderSize: len(compBytes),
		})

		if hasBody {
			bodyBytes := []byte(opts.Data)
			const maxFrameSize = 16384
			for offset := 0; offset < len(bodyBytes); offset += maxFrameSize {
				end := offset + maxFrameSize
				if end > len(bodyBytes) {
					end = len(bodyBytes)
				}
				chunk := bodyBytes[offset:end]
				isLastChunk := (end == len(bodyBytes))

				if err := framer.WriteData(streamID, isLastChunk, chunk); err != nil {
					return rec.Events(), fmt.Errorf("failed to write data for stream %d: %w", streamID, err)
				}

				cBefore := sendConnWindow
				sendConnWindow -= int64(len(chunk))
				cAfter := sendConnWindow

				sBefore := sendStreamWindows[streamID]
				sendStreamWindows[streamID] -= int64(len(chunk))
				sAfter := sendStreamWindows[streamID]

				var dataFlags uint8
				var dataFlagNames []string
				if isLastChunk {
					dataFlags = 0x1
					dataFlagNames = []string{"END_STREAM"}
				}

				var payload []byte
				if opts.ShowBody {
					payload = chunk
				}

				rec.RecordEvent(event.FrameEvent{
					Timestamp:          time.Since(connStart),
					Direction:          event.DirSend,
					StreamID:           streamID,
					FrameType:          event.FrameData,
					Length:             len(chunk),
					Flags:              dataFlags,
					FlagNames:          dataFlagNames,
					ConnWindowBefore:   cBefore,
					ConnWindowAfter:    cAfter,
					StreamWindowBefore: sBefore,
					StreamWindowAfter:  sAfter,
					Payload:            payload,
				})
			}
		}
	}

	// Read loop until all active streams and pending PING complete or timeout
	_ = conn.SetDeadline(time.Now().Add(timeout))

	for len(activeStreams) > 0 || pingPending {
		f, err := framer.ReadFrame()
		if err != nil {
			if err == io.EOF {
				break
			}
			return rec.Events(), fmt.Errorf("error reading frame: %w", err)
		}

		now := time.Since(connStart)

		switch fr := f.(type) {
		case *http2.SettingsFrame:
			var flagNames []string
			var details []string
			if fr.IsAck() {
				flagNames = append(flagNames, "ACK")
			} else {
				_ = framer.WriteSettingsAck()
				rec.RecordEvent(event.FrameEvent{
					Timestamp: time.Since(connStart),
					Direction: event.DirSend,
					StreamID:  0,
					FrameType: event.FrameSettings,
					Length:    0,
					Flags:     0x1,
					FlagNames: []string{"ACK"},
				})

				_ = fr.ForeachSetting(func(s http2.Setting) error {
					valStr := fmt.Sprintf("%d", s.Val)
					if s.ID == http2.SettingInitialWindowSize && s.Val >= 1048576 {
						valStr = fmt.Sprintf("%d (%dMB)", s.Val, s.Val/1048576)
					}
					details = append(details, fmt.Sprintf("%s: %s", s.ID.String(), valStr))
					return nil
				})
			}

			rec.RecordEvent(event.FrameEvent{
				Timestamp: now,
				Direction: event.DirRecv,
				StreamID:  fr.StreamID,
				FrameType: event.FrameSettings,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				FlagNames: flagNames,
				Details:   details,
			})

		case *http2.MetaHeadersFrame:
			var flagNames []string
			if fr.HeadersEnded() {
				flagNames = append(flagNames, "END_HEADERS")
			}
			if fr.StreamEnded() {
				flagNames = append(flagNames, "END_STREAM")
				delete(activeStreams, fr.StreamID)
			}

			rawHeaderBytes := 0
			var respHeaders []event.HeaderField
			for _, hf := range fr.Fields {
				rawHeaderBytes += len(hf.Name) + len(hf.Value) + 32
				idxInfo := getIndexInfo(hf.Name, hf.Value, recvDynamicTable, &recvDynamicIndex)
				respHeaders = append(respHeaders, event.HeaderField{
					Name:      hf.Name,
					Value:     hf.Value,
					IndexInfo: idxInfo,
				})
			}

			rec.RecordEvent(event.FrameEvent{
				Timestamp:      now,
				Direction:      event.DirRecv,
				StreamID:       fr.StreamID,
				FrameType:      event.FrameHeaders,
				Length:         int(fr.Length),
				Flags:          uint8(fr.Flags),
				FlagNames:      flagNames,
				Headers:        respHeaders,
				RawHeaderSize:  rawHeaderBytes,
				CompHeaderSize: int(fr.Length),
			})

		case *http2.DataFrame:
			var flagNames []string
			if fr.StreamEnded() {
				flagNames = append(flagNames, "END_STREAM")
				delete(activeStreams, fr.StreamID)
			}

			cBefore := connWindow
			connWindow -= int64(fr.Length)
			cAfter := connWindow

			sBefore := streamWindows[fr.StreamID]
			streamWindows[fr.StreamID] -= int64(fr.Length)
			sAfter := streamWindows[fr.StreamID]

			var payload []byte
			if opts.ShowBody && len(fr.Data()) > 0 {
				payload = append([]byte(nil), fr.Data()...)
			}

			rec.RecordEvent(event.FrameEvent{
				Timestamp:          now,
				Direction:          event.DirRecv,
				StreamID:           fr.StreamID,
				FrameType:          event.FrameData,
				Length:             int(fr.Length),
				Flags:              uint8(fr.Flags),
				FlagNames:          flagNames,
				ConnWindowBefore:   cBefore,
				ConnWindowAfter:    cAfter,
				StreamWindowBefore: sBefore,
				StreamWindowAfter:  sAfter,
				Payload:            payload,
			})

			// Replenish connection window if below half
			if connWindow <= 65535/2 {
				inc := uint32(65535 - connWindow)
				if inc > 0 {
					_ = framer.WriteWindowUpdate(0, inc)
					oldWin := connWindow
					connWindow += int64(inc)
					rec.RecordEvent(event.FrameEvent{
						Timestamp: time.Since(connStart),
						Direction: event.DirSend,
						StreamID:  0,
						FrameType: event.FrameWindowUpdate,
						Length:    4,
						Flags:     0x0,
						Details:   []string{fmt.Sprintf("increment=%d [Conn Window: %d -> %d]", inc, oldWin, connWindow)},
					})
				}
			}

			// Replenish stream window if stream is still active and below half of initialWindowSize
			if !fr.StreamEnded() && streamWindows[fr.StreamID] <= int64(initialWindowSize)/2 {
				inc := uint32(int64(initialWindowSize) - streamWindows[fr.StreamID])
				if inc > 0 {
					_ = framer.WriteWindowUpdate(fr.StreamID, inc)
					oldWin := streamWindows[fr.StreamID]
					streamWindows[fr.StreamID] += int64(inc)
					rec.RecordEvent(event.FrameEvent{
						Timestamp: time.Since(connStart),
						Direction: event.DirSend,
						StreamID:  fr.StreamID,
						FrameType: event.FrameWindowUpdate,
						Length:    4,
						Flags:     0x0,
						Details:   []string{fmt.Sprintf("increment=%d [Stream %d Window: %d -> %d]", inc, fr.StreamID, oldWin, streamWindows[fr.StreamID])},
					})
				}
			}

		case *http2.WindowUpdateFrame:
			var details []string
			if fr.StreamID == 0 {
				cBefore := sendConnWindow
				sendConnWindow += int64(fr.Increment)
				details = append(details, fmt.Sprintf("[Conn Window: %d -> %d]", cBefore, sendConnWindow))
			} else {
				sBefore := sendStreamWindows[fr.StreamID]
				sendStreamWindows[fr.StreamID] += int64(fr.Increment)
				details = append(details, fmt.Sprintf("[Stream %d Window: %d -> %d]", fr.StreamID, sBefore, sendStreamWindows[fr.StreamID]))
			}

			rec.RecordEvent(event.FrameEvent{
				Timestamp: now,
				Direction: event.DirRecv,
				StreamID:  fr.StreamID,
				FrameType: event.FrameWindowUpdate,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				Details:   details,
			})

		case *http2.RSTStreamFrame:
			delete(activeStreams, fr.StreamID)
			rec.RecordEvent(event.FrameEvent{
				Timestamp: now,
				Direction: event.DirRecv,
				StreamID:  fr.StreamID,
				FrameType: event.FrameRSTStream,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				Details:   []string{fmt.Sprintf("ErrorCode: %s (0x%x)", fr.ErrCode.String(), uint32(fr.ErrCode))},
			})

		case *http2.GoAwayFrame:
			rec.RecordEvent(event.FrameEvent{
				Timestamp: now,
				Direction: event.DirRecv,
				StreamID:  fr.StreamID,
				FrameType: event.FrameGoAway,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				Details: []string{
					fmt.Sprintf("LastStreamID: %d, ErrCode: %s", fr.LastStreamID, fr.ErrCode.String()),
				},
			})
			return rec.Events(), nil

		case *http2.PingFrame:
			var flagNames []string
			var details []string
			if fr.IsAck() {
				flagNames = append(flagNames, "ACK")
				if pingPending {
					rtt := time.Since(pingSentAt)
					pingPending = false
					details = append(details, fmt.Sprintf("RTT: %.2fms", float64(rtt.Microseconds())/1000.0))
				}
			}
			rec.RecordEvent(event.FrameEvent{
				Timestamp: now,
				Direction: event.DirRecv,
				StreamID:  0,
				FrameType: event.FramePing,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				FlagNames: flagNames,
				Details:   details,
			})
			if !fr.IsAck() {
				_ = framer.WritePing(true, fr.Data)
				rec.RecordEvent(event.FrameEvent{
					Timestamp: time.Since(connStart),
					Direction: event.DirSend,
					StreamID:  0,
					FrameType: event.FramePing,
					Length:    8,
					Flags:     0x1,
					FlagNames: []string{"ACK"},
				})
			}
		}
	}

	return rec.Events(), nil
}
