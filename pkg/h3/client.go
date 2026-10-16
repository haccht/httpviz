package h3

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// Options is an alias for event.Options.
type Options = event.Options

type customTracer struct {
	rec *customRecorder
}

func (t *customTracer) AddProducer() qlogwriter.Recorder {
	return t.rec
}

func (t *customTracer) SupportsSchemas(schema string) bool {
	return true
}

type customRecorder struct {
	onEvent func(qlogwriter.Event)
}

func (r *customRecorder) RecordEvent(e qlogwriter.Event) {
	if r.onEvent != nil {
		r.onEvent(e)
	}
}

func (r *customRecorder) Close() error {
	return nil
}

func derefFrame(f any) any {
	switch v := f.(type) {
	case *qlog.StreamFrame:
		return *v
	case *qlog.AckFrame:
		return *v
	case *qlog.CryptoFrame:
		return *v
	case *qlog.PingFrame:
		return *v
	case *qlog.HandshakeDoneFrame:
		return *v
	case *qlog.ConnectionCloseFrame:
		return *v
	case *qlog.MaxDataFrame:
		return *v
	case *qlog.MaxStreamDataFrame:
		return *v
	case *qlog.ResetStreamFrame:
		return *v
	default:
		return f
	}
}

func derefEvent(ev qlogwriter.Event) any {
	switch v := ev.(type) {
	case *qlog.PacketSent:
		return *v
	case *qlog.PacketReceived:
		return *v
	default:
		return ev
	}
}

func extractSubEvents(frames []qlog.Frame) []event.FrameEvent {
	var subs []event.FrameEvent
	for _, fr := range frames {
		switch f := derefFrame(fr.Frame).(type) {
		case qlog.StreamFrame:
			var flags []string
			if f.Fin {
				flags = append(flags, "FIN")
			}
			subs = append(subs, event.FrameEvent{
				StreamID:  uint32(f.StreamID),
				FrameType: event.FrameStream,
				Length:    int(f.Length),
				FlagNames: flags,
				Details:   []string{fmt.Sprintf("offset=%d, fin=%v", f.Offset, f.Fin)},
			})
		case qlog.AckFrame:
			subs = append(subs, event.FrameEvent{
				FrameType: event.FrameAck,
				Details:   []string{fmt.Sprintf("ack_delay=%v", f.DelayTime)},
			})
		case qlog.CryptoFrame:
			subs = append(subs, event.FrameEvent{
				FrameType: event.FrameCrypto,
				Length:    int(f.Length),
				Details:   []string{fmt.Sprintf("offset=%d", f.Offset)},
			})
		case qlog.PingFrame:
			subs = append(subs, event.FrameEvent{
				FrameType: event.FramePing,
			})
		case qlog.HandshakeDoneFrame:
			subs = append(subs, event.FrameEvent{
				FrameType: event.FrameHandshakeDone,
			})
		case qlog.ConnectionCloseFrame:
			subs = append(subs, event.FrameEvent{
				FrameType: event.FrameConnectionClose,
				Details:   []string{fmt.Sprintf("code=0x%x, phrase=%s", f.ErrorCode, f.ReasonPhrase)},
			})
		case qlog.MaxDataFrame:
			subs = append(subs, event.FrameEvent{
				FrameType: event.FrameMaxData,
				Details:   []string{fmt.Sprintf("max=%d", f.MaximumData)},
			})
		case qlog.MaxStreamDataFrame:
			subs = append(subs, event.FrameEvent{
				StreamID:  uint32(f.StreamID),
				FrameType: event.FrameMaxStreamData,
				Details:   []string{fmt.Sprintf("max=%d", f.MaximumStreamData)},
			})
		case qlog.ResetStreamFrame:
			subs = append(subs, event.FrameEvent{
				StreamID:  uint32(f.StreamID),
				FrameType: event.FrameResetStream,
				Details:   []string{fmt.Sprintf("error_code=%v", f.ErrorCode)},
			})
		default:
			name := fmt.Sprintf("%T", fr.Frame)
			if dot := strings.LastIndex(name, "."); dot != -1 {
				name = name[dot+1:]
			}
			subs = append(subs, event.FrameEvent{
				FrameType: strings.ToUpper(strings.TrimSuffix(name, "Frame")),
			})
		}
	}
	return subs
}

// Run executes HTTP/3 requests to the given URLs and returns the recorded events.
func Run(rawURLs []string, opts Options) ([]event.FrameEvent, error) {
	if len(rawURLs) == 0 {
		return nil, nil
	}

	timeout := opts.EffectiveTimeout()
	method := opts.ResolveMethod()
	rec := event.NewRecorder(opts)

	connStart := time.Now()

	u0, err := url.Parse(rawURLs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURLs[0], err)
	}

	_, host, _ := event.NormalizeURL(u0, "https")
	_ = event.ResolveDNSIfNeeded(u0, host, timeout, connStart, opts.OnInfo)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.Insecure,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         u0.Hostname(),
	}

	var pathMu sync.Mutex
	streamIDsByPath := make(map[string][]uint32)

	recordPacket := func(now time.Duration, dir event.Direction, hdr qlog.PacketHeader, length int, frames []qlog.Frame) {
		rec.RecordEvent(event.FrameEvent{
			Timestamp: now,
			Direction: dir,
			FrameType: event.FrameQUICPacket,
			Length:    length,
			Details: []string{
				fmt.Sprintf("type=%s, num=%d", hdr.PacketType, hdr.PacketNumber),
			},
			SubEvents: extractSubEvents(frames),
		})
	}

	qlogRec := &customRecorder{
		onEvent: func(ev qlogwriter.Event) {
			now := time.Since(connStart)
			switch e := derefEvent(ev).(type) {
			case qlog.PacketSent:
				recordPacket(now, event.DirSend, e.Header, int(e.Raw.Length), e.Frames)
			case qlog.PacketReceived:
				recordPacket(now, event.DirRecv, e.Header, int(e.Raw.Length), e.Frames)
			case h3qlog.FrameCreated:
				switch f := e.Frame.Frame.(type) {
				case h3qlog.HeadersFrame:
					var headers []event.HeaderField
					var reqPath string
					for _, h := range f.HeaderFields {
						headers = append(headers, event.HeaderField{Name: h.Name, Value: h.Value})
						if h.Name == ":path" {
							reqPath = h.Value
						}
					}
					if reqPath != "" {
						pathMu.Lock()
						streamIDsByPath[reqPath] = append(streamIDsByPath[reqPath], uint32(e.StreamID))
						pathMu.Unlock()
					}
					rec.RecordEvent(event.FrameEvent{
						Timestamp: now,
						Direction: event.DirSend,
						StreamID:  uint32(e.StreamID),
						FrameType: event.FrameHeaders,
						Length:    e.Raw.Length,
						Headers:   headers,
					})
				case h3qlog.DataFrame:
					var payload []byte
					if opts.ShowBody && opts.Data != "" {
						payload = []byte(opts.Data)
					}
					rec.RecordEvent(event.FrameEvent{
						Timestamp: now,
						Direction: event.DirSend,
						StreamID:  uint32(e.StreamID),
						FrameType: event.FrameData,
						Length:    e.Raw.Length,
						Payload:   payload,
					})
				case h3qlog.SettingsFrame:
					rec.RecordEvent(event.FrameEvent{
						Timestamp: now,
						Direction: event.DirSend,
						StreamID:  uint32(e.StreamID),
						FrameType: event.FrameSettings,
						Length:    e.Raw.Length,
					})
				}
			case h3qlog.FrameParsed:
				switch f := e.Frame.Frame.(type) {
				case h3qlog.HeadersFrame:
					var headers []event.HeaderField
					for _, h := range f.HeaderFields {
						headers = append(headers, event.HeaderField{Name: h.Name, Value: h.Value})
					}
					rec.RecordEvent(event.FrameEvent{
						Timestamp: now,
						Direction: event.DirRecv,
						StreamID:  uint32(e.StreamID),
						FrameType: event.FrameHeaders,
						Length:    e.Raw.Length,
						Headers:   headers,
					})
				case h3qlog.DataFrame:
					if !opts.ShowBody {
						rec.RecordEvent(event.FrameEvent{
							Timestamp: now,
							Direction: event.DirRecv,
							StreamID:  uint32(e.StreamID),
							FrameType: event.FrameData,
							Length:    e.Raw.Length,
						})
					}
				case h3qlog.SettingsFrame:
					rec.RecordEvent(event.FrameEvent{
						Timestamp: now,
						Direction: event.DirRecv,
						StreamID:  uint32(e.StreamID),
						FrameType: event.FrameSettings,
						Length:    e.Raw.Length,
					})
				}
			}
		},
	}

	quicConf := &quic.Config{
		Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
			return &customTracer{rec: qlogRec}
		},
	}
	if opts.WindowSize > 0 {
		quicConf.InitialStreamReceiveWindow = uint64(opts.WindowSize)
	}

	roundTripper := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConf,
	}
	defer roundTripper.Close()

	rec.RecordInfo(fmt.Sprintf("* Connected to %s (QUIC, ALPN: %s)", host, http3.NextProtoH3), time.Since(connStart))

	client := &http.Client{
		Transport: roundTripper,
		Timeout:   timeout,
	}

	customHeaders := opts.ParseCustomHeaders()

	var wg sync.WaitGroup
	errCh := make(chan error, len(rawURLs))

	for i, rawU := range rawURLs {
		wg.Add(1)
		go func(idx int, uStr string) {
			defer wg.Done()
			var bodyReader io.Reader
			if opts.Data != "" {
				bodyReader = strings.NewReader(opts.Data)
			}
			req, err := http.NewRequestWithContext(context.Background(), method, uStr, bodyReader)
			if err != nil {
				errCh <- fmt.Errorf("failed to create request: %w", err)
				return
			}
			req.Header.Set("User-Agent", "httpviz/0.1.0")
			if opts.Data != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			for _, h := range customHeaders {
				req.Header.Set(h.Name, h.Value)
			}

			resp, err := client.Do(req)
			if err != nil {
				errCh <- fmt.Errorf("HTTP/3 request failed: %w", err)
				return
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				errCh <- fmt.Errorf("failed reading body: %w", err)
				return
			}

			if opts.ShowBody && len(body) > 0 {
				reqPath := req.URL.RequestURI()
				if reqPath == "" {
					reqPath = "/"
				}
				sid := uint32(idx * 4)
				pathMu.Lock()
				if sids := streamIDsByPath[reqPath]; len(sids) > 0 {
					sid = sids[0]
					streamIDsByPath[reqPath] = sids[1:]
				}
				pathMu.Unlock()

				rec.RecordEvent(event.FrameEvent{
					Timestamp: time.Since(connStart),
					Direction: event.DirRecv,
					StreamID:  sid,
					FrameType: event.FrameData,
					Length:    len(body),
					Payload:   body,
				})
			}
		}(i, rawU)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return rec.Events(), err
		}
	}

	return rec.Events(), nil
}
