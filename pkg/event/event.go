package event

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Direction string

const (
	DirSend Direction = "──>"
	DirRecv Direction = "<──"
)

// FrameType constants used across HTTP/1.x, HTTP/2, and HTTP/3.
const (
	FrameMagic           = "MAGIC"
	FrameSettings        = "SETTINGS"
	FrameHeaders         = "HEADERS"
	FrameData            = "DATA"
	FrameWindowUpdate    = "WINDOW_UPDATE"
	FrameGoAway          = "GOAWAY"
	FrameRSTStream       = "RST_STREAM"
	FramePing            = "PING"
	FrameQUICPacket      = "QUIC_PACKET"
	FrameRequestLine     = "REQUEST_LINE"
	FrameStatusLine      = "STATUS_LINE"
	FrameChunk           = "CHUNK"
	FrameStream          = "STREAM"
	FrameAck             = "ACK"
	FrameCrypto          = "CRYPTO"
	FrameHandshakeDone   = "HANDSHAKE_DONE"
	FrameConnectionClose = "CONNECTION_CLOSE"
	FrameMaxData         = "MAX_DATA"
	FrameMaxStreamData   = "MAX_STREAM_DATA"
	FrameResetStream     = "RESET_STREAM"
)

type HeaderField struct {
	Name      string
	Value     string
	IndexInfo string
}

type FrameEvent struct {
	Timestamp          time.Duration
	Direction          Direction
	StreamID           uint32
	FrameType          string
	Length             int
	Flags              uint8
	FlagNames          []string
	Details            []string
	Headers            []HeaderField
	RawHeaderSize      int
	CompHeaderSize     int
	ConnWindowBefore   int64
	ConnWindowAfter    int64
	StreamWindowBefore int64
	StreamWindowAfter  int64
	Payload            []byte
	PayloadLimit       int
	SubEvents          []FrameEvent
}

// Options holds common client configuration across HTTP/1.x, HTTP/2, and HTTP/3.
type Options struct {
	Method     string
	Data       string
	Headers    []string
	ShowBody   bool
	BodyLimit  int
	WindowSize uint32
	Ping       bool
	Insecure   bool
	Timeout    time.Duration
	OnEvent    func(FrameEvent)
	OnInfo     func(msg string, elapsed time.Duration)
	Conn       net.Conn
	ConnStart  time.Time
}

// EffectiveTimeout returns Timeout if positive, or the default 10s timeout.
func (o Options) EffectiveTimeout() time.Duration {
	if o.Timeout <= 0 {
		return 10 * time.Second
	}
	return o.Timeout
}

// ResolveMethod returns the normalized HTTP method (defaulting to POST when Data is non-empty, or GET).
func (o Options) ResolveMethod() string {
	m := strings.ToUpper(strings.TrimSpace(o.Method))
	if m != "" {
		return m
	}
	if o.Data != "" {
		return "POST"
	}
	return "GET"
}

// ParseCustomHeaders parses "Name: Value" strings from Options.Headers.
func (o Options) ParseCustomHeaders() []HeaderField {
	var out []HeaderField
	for _, rawHdr := range o.Headers {
		parts := strings.SplitN(rawHdr, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if name != "" {
				out = append(out, HeaderField{Name: name, Value: val})
			}
		}
	}
	return out
}

// NormalizeURL extracts normalized scheme, host:port, and request path from u.
func NormalizeURL(u *url.URL, defaultScheme string) (scheme, host, path string) {
	scheme = strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = defaultScheme
		u.Scheme = scheme
	}
	host = u.Host
	if !strings.Contains(host, ":") {
		if scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	path = u.RequestURI()
	if path == "" {
		path = "/"
	}
	return scheme, host, path
}

// Recorder provides thread-safe event and info recording for protocol clients.
type Recorder struct {
	mu     sync.Mutex
	events []FrameEvent
	opts   Options
}

// NewRecorder creates a Recorder bound to opts.
func NewRecorder(opts Options) *Recorder {
	return &Recorder{opts: opts}
}

// RecordEvent appends an event (applying BodyLimit if needed) and triggers OnEvent.
func (r *Recorder) RecordEvent(e FrameEvent) {
	if len(e.Payload) > 0 && e.PayloadLimit == 0 {
		e.PayloadLimit = r.opts.BodyLimit
	}
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	if r.opts.OnEvent != nil {
		r.opts.OnEvent(e)
	}
}

// RecordInfo triggers OnInfo if configured.
func (r *Recorder) RecordInfo(msg string, elapsed time.Duration) {
	if r.opts.OnInfo != nil {
		r.opts.OnInfo(msg, elapsed)
	}
}

// Events returns a snapshot of recorded FrameEvents.
func (r *Recorder) Events() []FrameEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]FrameEvent, len(r.events))
	copy(out, r.events)
	return out
}
