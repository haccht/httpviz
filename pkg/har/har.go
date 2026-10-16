package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"golang.org/x/net/http2/hpack"
)

// File represents the top-level HAR 1.2 JSON structure.
type File struct {
	Log Log `json:"log"`
}

// Log contains the list of captured HTTP entries.
type Log struct {
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`
}

// Entry represents a single HTTP request/response pair in HAR.
type Entry struct {
	StartedDateTime string           `json:"startedDateTime"`
	Time            float64          `json:"time"`
	Request         Request          `json:"request"`
	Response        Response         `json:"response"`
	Timings         Timings          `json:"timings"`
	ServerIPAddress string           `json:"serverIPAddress"`
	Connection      string           `json:"connection"`
	SecurityDetails *SecurityDetails `json:"_securityDetails,omitempty"`
}

// SecurityDetails holds optional TLS details exported by browsers (e.g. Chrome DevTools).
type SecurityDetails struct {
	Protocol string `json:"protocol"`
	Cipher   string `json:"cipher"`
}

// Request represents the HAR request object.
type Request struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Headers     []Header `json:"headers"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
	PostData    *Post    `json:"postData,omitempty"`
}

// Post represents the HAR request payload.
type Post struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// Response represents the HAR response object.
type Response struct {
	Status      int      `json:"status"`
	StatusText  string   `json:"statusText"`
	HTTPVersion string   `json:"httpVersion"`
	Headers     []Header `json:"headers"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
	Content     Content  `json:"content"`
}

// Content represents the HAR response body content.
type Content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
}

// Header represents a name-value HTTP header pair in HAR.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Timings represents HAR 1.2 phase durations in milliseconds (-1 means not applicable).
type Timings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	SSL     float64 `json:"ssl"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func normalizeProto(ver string) string {
	v := strings.ToLower(strings.TrimSpace(ver))
	switch {
	case v == "h2" || v == "h2c" || strings.HasPrefix(v, "http/2"):
		return "h2"
	case v == "h3" || strings.HasPrefix(v, "h3-") || strings.HasPrefix(v, "http/3") || v == "quic":
		return "h3"
	default:
		return "h1"
	}
}

func msToDuration(ms float64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

func parseHARTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z07:00",
		"2006-01-02T15:04:05.000Z",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func decodeContent(c Content) []byte {
	if c.Text == "" {
		return nil
	}
	if strings.EqualFold(c.Encoding, "base64") {
		if b, err := base64.StdEncoding.DecodeString(c.Text); err == nil {
			return b
		}
	}
	return []byte(c.Text)
}

var h2StaticTable = map[string]struct {
	Index    int
	HasValue bool
}{
	":authority":                    {1, false},
	":method:GET":                   {2, true},
	":method:POST":                  {3, true},
	":path:/":                       {4, true},
	":path:/index.html":             {5, true},
	":scheme:http":                  {6, true},
	":scheme:https":                 {7, true},
	":status:200":                   {8, true},
	":status:204":                   {9, true},
	":status:206":                   {10, true},
	":status:304":                   {11, true},
	":status:400":                   {12, true},
	":status:404":                   {13, true},
	":status:500":                   {14, true},
	"accept-encoding:gzip, deflate": {16, true},
	"accept-language":               {17, false},
	"accept":                        {19, false},
	"cache-control":                 {24, false},
	"content-encoding":              {26, false},
	"content-length":                {28, false},
	"content-type":                  {31, false},
	"cookie":                        {32, false},
	"date":                          {33, false},
	"etag":                          {34, false},
	"host":                          {38, false},
	"location":                      {46, false},
	"server":                        {54, false},
	"set-cookie":                    {55, false},
	"user-agent":                    {58, false},
}

func getHPACKIndexInfo(name, value string, dyn map[string]int, nextIdx *int) string {
	key := name + ":" + value
	if e, ok := h2StaticTable[key]; ok && e.HasValue {
		return fmt.Sprintf("Static Index: %d", e.Index)
	}
	if dyn != nil {
		if idx, ok := dyn[key]; ok {
			return fmt.Sprintf("Dynamic Index: %d", idx)
		}
		if nextIdx != nil && *nextIdx > 0 {
			idx := *nextIdx
			*nextIdx++
			dyn[key] = idx
			return fmt.Sprintf("Literal, Indexed -> Dynamic Index: %d", idx)
		}
	}
	if e, ok := h2StaticTable[name]; ok {
		return fmt.Sprintf("Literal, Indexed (Name Index: %d)", e.Index)
	}
	return "Literal, Indexed"
}

type timedEvent struct {
	isInfo bool
	info   string
	ts     time.Duration
	order  int
	ev     event.FrameEvent
}

// Run parses a HAR 1.2 stream and emits connection info and FrameEvents.
func Run(r io.Reader, opts event.Options) ([]event.FrameEvent, error) {
	var harFile File
	dec := json.NewDecoder(r)
	if err := dec.Decode(&harFile); err != nil {
		return nil, fmt.Errorf("failed to parse HAR JSON: %w", err)
	}

	if len(harFile.Log.Entries) == 0 {
		return nil, fmt.Errorf("HAR file contains no entries")
	}

	// Filter entries by protocol if requested
	var entries []Entry
	for _, e := range harFile.Log.Entries {
		proto := normalizeProto(e.Request.HTTPVersion)
		if e.Response.HTTPVersion != "" && proto == "h1" {
			proto = normalizeProto(e.Response.HTTPVersion)
		}
		if opts.ProtocolFilter != "" && opts.ProtocolFilter != proto {
			continue
		}
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no HAR entries matched protocol filter %q", opts.ProtocolFilter)
	}

	// Determine base start time across entries
	var baseTime time.Time
	hasBaseTime := false
	for _, e := range entries {
		if t, ok := parseHARTime(e.StartedDateTime); ok {
			if !hasBaseTime || t.Before(baseTime) {
				baseTime = t
				hasBaseTime = true
			}
		}
	}

	var items []timedEvent
	orderSeq := 0
	addInfo := func(msg string, ts time.Duration) {
		orderSeq++
		items = append(items, timedEvent{
			isInfo: true,
			info:   msg,
			ts:     ts,
			order:  orderSeq,
		})
	}
	addEvent := func(ev event.FrameEvent) {
		orderSeq++
		items = append(items, timedEvent{
			isInfo: false,
			ts:     ev.Timestamp,
			order:  orderSeq,
			ev:     ev,
		})
	}

	var hpackBuf bytes.Buffer
	hpackEnc := hpack.NewEncoder(&hpackBuf)
	sendDyn := make(map[string]int)
	sendDynIdx := 62
	recvDyn := make(map[string]int)
	recvDynIdx := 62
	var fallbackOffset time.Duration

	for idx, entry := range entries {
		proto := normalizeProto(entry.Request.HTTPVersion)
		if entry.Response.HTTPVersion != "" && proto == "h1" {
			proto = normalizeProto(entry.Response.HTTPVersion)
		}

		var entryStart time.Duration
		if t, ok := parseHARTime(entry.StartedDateTime); ok && hasBaseTime {
			entryStart = t.Sub(baseTime)
			if entryStart < 0 {
				entryStart = 0
			}
		} else {
			entryStart = fallbackOffset
		}

		u, err := url.Parse(entry.Request.URL)
		if err != nil {
			u = &url.URL{Scheme: "https", Host: "unknown", Path: entry.Request.URL}
		}
		scheme, hostPort, path := event.NormalizeURL(u, "https")
		hostname := u.Hostname()
		if hostname == "" {
			hostname = hostPort
		}
		targetAddr := hostPort
		if entry.ServerIPAddress != "" {
			_, port, splitErr := net.SplitHostPort(hostPort)
			if splitErr != nil {
				if scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			targetAddr = net.JoinHostPort(strings.Trim(entry.ServerIPAddress, "[]"), port)
		}

		cur := entryStart + msToDuration(entry.Timings.Blocked)

		// 1. DNS timing
		if entry.Timings.DNS > 0 {
			cur += msToDuration(entry.Timings.DNS)
			ip := entry.ServerIPAddress
			if ip == "" {
				ip = hostname
			}
			addInfo(fmt.Sprintf("* DNS Lookup: %s -> %s (%.1fms)", hostname, ip, entry.Timings.DNS), cur)
		}

		// 2. TCP / QUIC & TLS connection timings
		if entry.Timings.Connect > 0 || entry.Timings.SSL > 0 {
			tcpMs := entry.Timings.Connect
			sslMs := entry.Timings.SSL
			if tcpMs > sslMs && sslMs > 0 {
				tcpMs -= sslMs
			}
			if proto == "h3" {
				handshakeMs := entry.Timings.Connect
				if sslMs > handshakeMs {
					handshakeMs = sslMs
				}
				cur += msToDuration(handshakeMs)
				addInfo(fmt.Sprintf("* Connected to %s (QUIC, ALPN: h3, %.1fms)", targetAddr, handshakeMs), cur)
			} else if scheme == "https" || sslMs > 0 {
				if tcpMs > 0 {
					cur += msToDuration(tcpMs)
					addInfo(fmt.Sprintf("* TCP Connected to %s (%.1fms)", targetAddr, tcpMs), cur)
				}
				tlsVer := "TLSv1.3"
				cipher := "TLS_AES_128_GCM_SHA256"
				if entry.SecurityDetails != nil {
					if entry.SecurityDetails.Protocol != "" {
						tlsVer = strings.ReplaceAll(entry.SecurityDetails.Protocol, " ", "v")
					}
					if entry.SecurityDetails.Cipher != "" {
						cipher = entry.SecurityDetails.Cipher
					}
				}
				alpn := "http/1.1"
				if proto == "h2" {
					alpn = "h2"
				}
				if sslMs > 0 {
					cur += msToDuration(sslMs)
					addInfo(fmt.Sprintf("* TLS Handshake: %s, Cipher: %s (%.1fms)", tlsVer, cipher, sslMs), cur)
				}
				addInfo(fmt.Sprintf("* Connected to %s (%s, ALPN: %s)", targetAddr, tlsVer, alpn), cur)
			} else {
				cur += msToDuration(tcpMs)
				addInfo(fmt.Sprintf("* Connected to %s (TCP, %.1fms)", targetAddr, tcpMs), cur)
			}
		}

		// Assign Stream ID
		var streamID uint32
		if proto == "h2" || proto == "h3" {
			streamID = uint32(idx*2 + 1)
		} else if len(entries) > 1 {
			streamID = uint32(idx + 1)
		} else {
			streamID = 0
		}

		method := entry.Request.Method
		if method == "" {
			method = "GET"
		}
		var reqBody []byte
		if entry.Request.PostData != nil && entry.Request.PostData.Text != "" {
			reqBody = []byte(entry.Request.PostData.Text)
		}
		hasReqBody := len(reqBody) > 0 || entry.Request.BodySize > 0

		// 3. Request Events
		reqTime := cur
		sendDur := msToDuration(entry.Timings.Send)
		reqEnd := reqTime + sendDur

		if proto == "h1" {
			httpVer := entry.Request.HTTPVersion
			if httpVer == "" || !strings.HasPrefix(strings.ToUpper(httpVer), "HTTP/") {
				httpVer = "HTTP/1.1"
			}
			reqLine := fmt.Sprintf("%s %s %s", method, path, strings.ToUpper(httpVer))
			addEvent(event.FrameEvent{
				Timestamp: reqTime,
				Direction: event.DirSend,
				StreamID:  streamID,
				FrameType: event.FrameRequestLine,
				Details:   []string{reqLine},
			})

			var reqHeaders []event.HeaderField
			rawLen := 0
			for _, h := range entry.Request.Headers {
				if strings.HasPrefix(h.Name, ":") {
					continue
				}
				reqHeaders = append(reqHeaders, event.HeaderField{Name: h.Name, Value: h.Value})
				rawLen += len(h.Name) + len(h.Value) + 4
			}
			if entry.Request.HeadersSize > 0 {
				rawLen = entry.Request.HeadersSize
			}
			addEvent(event.FrameEvent{
				Timestamp:     reqTime,
				Direction:     event.DirSend,
				StreamID:      streamID,
				FrameType:     event.FrameHeaders,
				Length:        rawLen,
				Headers:       reqHeaders,
				RawHeaderSize: rawLen,
			})

			if hasReqBody {
				bodyLen := len(reqBody)
				if bodyLen == 0 && entry.Request.BodySize > 0 {
					bodyLen = entry.Request.BodySize
				}
				var payload []byte
				if opts.ShowBody && len(reqBody) > 0 {
					payload = reqBody
				}
				addEvent(event.FrameEvent{
					Timestamp: reqEnd,
					Direction: event.DirSend,
					StreamID:  streamID,
					FrameType: event.FrameData,
					Length:    bodyLen,
					Details:   []string{fmt.Sprintf("body bytes: %d", bodyLen)},
					Payload:   payload,
				})
			}
		} else {
			// HTTP/2 or HTTP/3 request HEADERS
			reqHeaders := []event.HeaderField{
				{Name: ":method", Value: method},
				{Name: ":path", Value: path},
				{Name: ":scheme", Value: scheme},
				{Name: ":authority", Value: u.Host},
			}
			for _, h := range entry.Request.Headers {
				lower := strings.ToLower(h.Name)
				if strings.HasPrefix(lower, ":") || lower == "host" {
					continue
				}
				reqHeaders = append(reqHeaders, event.HeaderField{Name: lower, Value: h.Value})
			}

			hpackBuf.Reset()
			rawLen := 0
			for i := range reqHeaders {
				rawLen += len(reqHeaders[i].Name) + len(reqHeaders[i].Value) + 32
				_ = hpackEnc.WriteField(hpack.HeaderField{Name: reqHeaders[i].Name, Value: reqHeaders[i].Value})
				if proto == "h2" {
					reqHeaders[i].IndexInfo = getHPACKIndexInfo(reqHeaders[i].Name, reqHeaders[i].Value, sendDyn, &sendDynIdx)
				}
			}
			compLen := hpackBuf.Len()
			if entry.Request.HeadersSize > 0 {
				compLen = entry.Request.HeadersSize
			}

			var flags uint8 = 0x5
			flagNames := []string{"END_HEADERS", "END_STREAM"}
			if hasReqBody {
				flags = 0x4
				flagNames = []string{"END_HEADERS"}
			}
			if proto == "h3" {
				flags = 0
				flagNames = nil
			}

			ev := event.FrameEvent{
				Timestamp: reqTime,
				Direction: event.DirSend,
				StreamID:  streamID,
				FrameType: event.FrameHeaders,
				Length:    compLen,
				Flags:     flags,
				FlagNames: flagNames,
				Headers:   reqHeaders,
			}
			if proto == "h2" {
				ev.RawHeaderSize = rawLen
				ev.CompHeaderSize = compLen
			}
			addEvent(ev)

			if hasReqBody {
				bodyLen := len(reqBody)
				if bodyLen == 0 && entry.Request.BodySize > 0 {
					bodyLen = entry.Request.BodySize
				}
				var payload []byte
				if opts.ShowBody && len(reqBody) > 0 {
					payload = reqBody
				}
				var dFlags uint8
				var dFlagNames []string
				if proto == "h2" {
					dFlags = 0x1
					dFlagNames = []string{"END_STREAM"}
				}
				addEvent(event.FrameEvent{
					Timestamp: reqEnd,
					Direction: event.DirSend,
					StreamID:  streamID,
					FrameType: event.FrameData,
					Length:    bodyLen,
					Flags:     dFlags,
					FlagNames: dFlagNames,
					Payload:   payload,
				})
			}
		}

		// 4. Response Events
		respStart := reqEnd + msToDuration(entry.Timings.Wait)
		respEnd := respStart + msToDuration(entry.Timings.Receive)
		respBody := decodeContent(entry.Response.Content)
		respBodyLen := len(respBody)
		if respBodyLen == 0 {
			if entry.Response.Content.Size > 0 {
				respBodyLen = entry.Response.Content.Size
			} else if entry.Response.BodySize > 0 {
				respBodyLen = entry.Response.BodySize
			}
		}
		hasRespBody := respBodyLen > 0 && method != "HEAD"

		status := entry.Response.Status
		if status == 0 {
			status = 200
		}
		statusText := strings.TrimSpace(entry.Response.StatusText)
		if statusText == "" {
			statusText = http.StatusText(status)
		}

		if proto == "h1" {
			httpVer := entry.Response.HTTPVersion
			if httpVer == "" || !strings.HasPrefix(strings.ToUpper(httpVer), "HTTP/") {
				httpVer = "HTTP/1.1"
			}
			statusLine := fmt.Sprintf("%s %d", strings.ToUpper(httpVer), status)
			if statusText != "" {
				statusLine += " " + statusText
			}
			addEvent(event.FrameEvent{
				Timestamp: respStart,
				Direction: event.DirRecv,
				StreamID:  streamID,
				FrameType: event.FrameStatusLine,
				Details:   []string{statusLine},
			})

			var respHeaders []event.HeaderField
			rawLen := 0
			for _, h := range entry.Response.Headers {
				if strings.HasPrefix(h.Name, ":") {
					continue
				}
				respHeaders = append(respHeaders, event.HeaderField{Name: h.Name, Value: h.Value})
				rawLen += len(h.Name) + len(h.Value) + 4
			}
			if entry.Response.HeadersSize > 0 {
				rawLen = entry.Response.HeadersSize
			}
			addEvent(event.FrameEvent{
				Timestamp:     respStart,
				Direction:     event.DirRecv,
				StreamID:      streamID,
				FrameType:     event.FrameHeaders,
				Length:        rawLen,
				Headers:       respHeaders,
				RawHeaderSize: rawLen,
			})

			if hasRespBody {
				var payload []byte
				if opts.ShowBody && len(respBody) > 0 {
					payload = respBody
				}
				addEvent(event.FrameEvent{
					Timestamp: respEnd,
					Direction: event.DirRecv,
					StreamID:  streamID,
					FrameType: event.FrameData,
					Length:    respBodyLen,
					Details:   []string{fmt.Sprintf("body bytes: %d", respBodyLen)},
					Payload:   payload,
				})
			}
		} else {
			respHeaders := []event.HeaderField{
				{Name: ":status", Value: strconv.Itoa(status)},
			}
			for _, h := range entry.Response.Headers {
				lower := strings.ToLower(h.Name)
				if strings.HasPrefix(lower, ":") {
					continue
				}
				respHeaders = append(respHeaders, event.HeaderField{Name: lower, Value: h.Value})
			}

			hpackBuf.Reset()
			rawLen := 0
			for i := range respHeaders {
				rawLen += len(respHeaders[i].Name) + len(respHeaders[i].Value) + 32
				_ = hpackEnc.WriteField(hpack.HeaderField{Name: respHeaders[i].Name, Value: respHeaders[i].Value})
				if proto == "h2" {
					respHeaders[i].IndexInfo = getHPACKIndexInfo(respHeaders[i].Name, respHeaders[i].Value, recvDyn, &recvDynIdx)
				}
			}
			compLen := hpackBuf.Len()
			if entry.Response.HeadersSize > 0 {
				compLen = entry.Response.HeadersSize
			}

			var flags uint8 = 0x5
			flagNames := []string{"END_HEADERS", "END_STREAM"}
			if hasRespBody {
				flags = 0x4
				flagNames = []string{"END_HEADERS"}
			}
			if proto == "h3" {
				flags = 0
				flagNames = nil
			}

			ev := event.FrameEvent{
				Timestamp: respStart,
				Direction: event.DirRecv,
				StreamID:  streamID,
				FrameType: event.FrameHeaders,
				Length:    compLen,
				Flags:     flags,
				FlagNames: flagNames,
				Headers:   respHeaders,
			}
			if proto == "h2" {
				ev.RawHeaderSize = rawLen
				ev.CompHeaderSize = compLen
			}
			addEvent(ev)

			if hasRespBody {
				var payload []byte
				if opts.ShowBody && len(respBody) > 0 {
					payload = respBody
				}
				var dFlags uint8
				var dFlagNames []string
				if proto == "h2" {
					dFlags = 0x1
					dFlagNames = []string{"END_STREAM"}
				}
				addEvent(event.FrameEvent{
					Timestamp: respEnd,
					Direction: event.DirRecv,
					StreamID:  streamID,
					FrameType: event.FrameData,
					Length:    respBodyLen,
					Flags:     dFlags,
					FlagNames: dFlagNames,
					Payload:   payload,
				})
			}
		}

		if entry.Time > 0 {
			fallbackOffset = entryStart + msToDuration(entry.Time)
		} else {
			fallbackOffset = respEnd + 5*time.Millisecond
		}
	}

	// Sort all info and frame events chronologically
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ts == items[j].ts {
			return items[i].order < items[j].order
		}
		return items[i].ts < items[j].ts
	})

	rec := event.NewRecorder(opts)
	for _, item := range items {
		if item.isInfo {
			rec.RecordInfo(item.info, item.ts)
		} else {
			rec.RecordEvent(item.ev)
		}
	}

	return rec.Events(), nil
}
