package h1

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/haccht/httpviz/pkg/event"
)

// Options is an alias for event.Options.
type Options = event.Options

// Run executes HTTP/1.x requests to the provided URLs sequentially (reusing keep-alive connections when possible)
// and returns the recorded events.
func Run(rawURLs []string, opts Options) ([]event.FrameEvent, error) {
	if len(rawURLs) == 0 {
		return nil, nil
	}

	timeout := opts.EffectiveTimeout()
	method := opts.ResolveMethod()
	rec := event.NewRecorder(opts)

	connStart := time.Now()
	var currentConn net.Conn
	var currentHost string
	var currentScheme string
	var reader *bufio.Reader

	if opts.Conn != nil {
		u0, err := url.Parse(rawURLs[0])
		if err == nil {
			s0, h0, _ := event.NormalizeURL(u0, "https")
			currentConn = opts.Conn
			currentHost = h0
			currentScheme = s0
			reader = bufio.NewReader(currentConn)
			if !opts.ConnStart.IsZero() {
				connStart = opts.ConnStart
			}
		}
	}

	defer func() {
		if currentConn != nil {
			_ = currentConn.Close()
		}
	}()

	if opts.Ping {
		rec.RecordInfo("* Note: --ping is only supported on HTTP/2 (ignored for HTTP/1.1)", time.Since(connStart))
	}

	customHeaders := opts.ParseCustomHeaders()

	for i, rawURL := range rawURLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			return rec.Events(), fmt.Errorf("invalid URL %q: %w", rawURL, err)
		}

		scheme, host, path := event.NormalizeURL(u, "http")

		needNewConn := currentConn == nil || currentHost != host || currentScheme != scheme
		if needNewConn {
			if currentConn != nil {
				_ = currentConn.Close()
				currentConn = nil
			}

			conn, _, dialStart, err := event.DialTCPOrTLS(u, scheme, host, []string{"http/1.1"}, "", opts)
			if err != nil {
				return rec.Events(), err
			}
			connStart = dialStart
			currentConn = conn
			currentHost = host
			currentScheme = scheme
			reader = bufio.NewReader(currentConn)
		} else if i > 0 {
			rec.RecordInfo(fmt.Sprintf("* Reusing existing connection to %s (Request #%d)", currentHost, i+1), time.Since(connStart))
		}

		// Build HTTP/1.1 Request
		reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
		rec.RecordEvent(event.FrameEvent{
			Timestamp: time.Since(connStart),
			Direction: event.DirSend,
			FrameType: event.FrameRequestLine,
			Details:   []string{strings.TrimRight(reqLine, "\r\n")},
		})

		reqHeaders := []event.HeaderField{
			{Name: "Host", Value: u.Host},
			{Name: "User-Agent", Value: "httpviz/0.1.0"},
			{Name: "Connection", Value: "keep-alive"},
		}

		setOrAppendHeader := func(name, val string) {
			for idx := range reqHeaders {
				if strings.EqualFold(reqHeaders[idx].Name, name) {
					reqHeaders[idx].Name = name
					reqHeaders[idx].Value = val
					return
				}
			}
			reqHeaders = append(reqHeaders, event.HeaderField{Name: name, Value: val})
		}

		if len(opts.Data) > 0 {
			setOrAppendHeader("Content-Type", "application/x-www-form-urlencoded")
			setOrAppendHeader("Content-Length", strconv.Itoa(len(opts.Data)))
		}

		for _, h := range customHeaders {
			setOrAppendHeader(h.Name, h.Value)
		}

		var rawReq strings.Builder
		rawReq.WriteString(reqLine)
		for _, h := range reqHeaders {
			rawReq.WriteString(fmt.Sprintf("%s: %s\r\n", h.Name, h.Value))
		}
		rawReq.WriteString("\r\n")

		headerBytes := []byte(rawReq.String()[len(reqLine):])
		rec.RecordEvent(event.FrameEvent{
			Timestamp:     time.Since(connStart),
			Direction:     event.DirSend,
			FrameType:     event.FrameHeaders,
			Length:        len(headerBytes),
			Headers:       reqHeaders,
			RawHeaderSize: len(headerBytes),
		})

		// Send request headers (and body if present)
		if err := currentConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return rec.Events(), err
		}
		if _, err := currentConn.Write([]byte(rawReq.String())); err != nil {
			return rec.Events(), fmt.Errorf("failed to write request: %w", err)
		}

		if len(opts.Data) > 0 {
			bodyBytes := []byte(opts.Data)
			if _, err := currentConn.Write(bodyBytes); err != nil {
				return rec.Events(), fmt.Errorf("failed to write request body: %w", err)
			}
			var payload []byte
			if opts.ShowBody {
				payload = bodyBytes
			}
			rec.RecordEvent(event.FrameEvent{
				Timestamp: time.Since(connStart),
				Direction: event.DirSend,
				FrameType: event.FrameData,
				Length:    len(bodyBytes),
				Details:   []string{fmt.Sprintf("body bytes: %d", len(bodyBytes))},
				Payload:   payload,
			})
		}

		// Read response status line
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			return rec.Events(), fmt.Errorf("failed to read status line: %w", err)
		}
		rec.RecordEvent(event.FrameEvent{
			Timestamp: time.Since(connStart),
			Direction: event.DirRecv,
			FrameType: event.FrameStatusLine,
			Details:   []string{strings.TrimRight(statusLine, "\r\n")},
		})

		// Read response headers
		var respHeaders []event.HeaderField
		var totalHeaderLen int
		isChunked := false
		var contentLength int64 = -1
		keepAliveVal := ""
		connectionVal := ""

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return rec.Events(), fmt.Errorf("failed to read response headers: %w", err)
			}
			totalHeaderLen += len(line)
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break
			}
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				respHeaders = append(respHeaders, event.HeaderField{
					Name:  name,
					Value: val,
				})

				lowerName := strings.ToLower(name)
				if lowerName == "transfer-encoding" && strings.Contains(strings.ToLower(val), "chunked") {
					isChunked = true
				} else if lowerName == "content-length" {
					if cl, err := strconv.ParseInt(val, 10, 64); err == nil {
						contentLength = cl
					}
				} else if lowerName == "keep-alive" {
					keepAliveVal = val
				} else if lowerName == "connection" {
					connectionVal = val
				}
			}
		}

		rec.RecordEvent(event.FrameEvent{
			Timestamp:     time.Since(connStart),
			Direction:     event.DirRecv,
			FrameType:     event.FrameHeaders,
			Length:        totalHeaderLen,
			Headers:       respHeaders,
			RawHeaderSize: totalHeaderLen,
		})

		// Read Body (unless HEAD request)
		if method != "HEAD" && isChunked {
			chunkIndex := 1
			for {
				sizeLine, err := reader.ReadString('\n')
				if err != nil {
					return rec.Events(), fmt.Errorf("failed to read chunk size: %w", err)
				}
				sizeTrimmed := strings.TrimSpace(sizeLine)
				if semi := strings.Index(sizeTrimmed, ";"); semi != -1 {
					sizeTrimmed = sizeTrimmed[:semi]
				}
				chunkSize, err := strconv.ParseInt(sizeTrimmed, 16, 64)
				if err != nil {
					return rec.Events(), fmt.Errorf("invalid chunk size %q: %w", sizeTrimmed, err)
				}

				if chunkSize == 0 {
					for {
						tLine, err := reader.ReadString('\n')
						if err != nil || strings.TrimRight(tLine, "\r\n") == "" {
							break
						}
					}
					rec.RecordEvent(event.FrameEvent{
						Timestamp: time.Since(connStart),
						Direction: event.DirRecv,
						FrameType: event.FrameChunk,
						Length:    0,
						Details:   []string{fmt.Sprintf("size=0B, chunk #%d, [FIN]", chunkIndex)},
					})
					break
				}

				data := make([]byte, chunkSize)
				if _, err := io.ReadFull(reader, data); err != nil {
					return rec.Events(), fmt.Errorf("failed to read chunk data: %w", err)
				}
				if _, err := reader.ReadString('\n'); err != nil {
					return rec.Events(), fmt.Errorf("failed to read chunk trailer CRLF: %w", err)
				}

				var payload []byte
				if opts.ShowBody {
					payload = data
				}
				rec.RecordEvent(event.FrameEvent{
					Timestamp: time.Since(connStart),
					Direction: event.DirRecv,
					FrameType: event.FrameChunk,
					Length:    int(chunkSize),
					Details:   []string{fmt.Sprintf("size=%dB, chunk #%d", chunkSize, chunkIndex)},
					Payload:   payload,
				})
				chunkIndex++
			}
		} else if method != "HEAD" && contentLength > 0 {
			remaining := contentLength
			for remaining > 0 {
				toRead := remaining
				if toRead > 16384 {
					toRead = 16384
				}
				buf := make([]byte, toRead)
				n, err := io.ReadFull(reader, buf)
				if err != nil {
					return rec.Events(), fmt.Errorf("failed reading body: %w", err)
				}
				remaining -= int64(n)
				var payload []byte
				if opts.ShowBody {
					payload = buf[:n]
				}
				rec.RecordEvent(event.FrameEvent{
					Timestamp: time.Since(connStart),
					Direction: event.DirRecv,
					FrameType: event.FrameData,
					Length:    n,
					Details:   []string{fmt.Sprintf("body bytes: %d", n)},
					Payload:   payload,
				})
			}
		}

		// Keep-Alive status reporting
		if strings.EqualFold(connectionVal, "close") {
			rec.RecordInfo("* Connection closed by server", time.Since(connStart))
			_ = currentConn.Close()
			currentConn = nil
		} else {
			msg := "* Connection kept alive"
			if keepAliveVal != "" {
				msg += fmt.Sprintf(" (Keep-Alive: %s)", keepAliveVal)
			}
			rec.RecordInfo(msg, time.Since(connStart))
		}
	}

	return rec.Events(), nil
}
