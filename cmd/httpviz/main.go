package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"github.com/haccht/httpviz/pkg/h1"
	"github.com/haccht/httpviz/pkg/h2"
	"github.com/haccht/httpviz/pkg/h3"
	"github.com/haccht/httpviz/pkg/render"
	"github.com/spf13/pflag"
)

type bodyLimitValue struct {
	limit *int
}

func (b *bodyLimitValue) String() string {
	if b.limit == nil || *b.limit < 0 {
		return ""
	}
	return strconv.Itoa(*b.limit)
}

func (b *bodyLimitValue) Set(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return fmt.Errorf("invalid byte limit %q (must be >= 0)", s)
	}
	*b.limit = v
	return nil
}

func (b *bodyLimitValue) Type() string {
	return "int"
}

func normalizeBodyArgs(args []string) []string {
	takesValue := map[string]bool{
		"-X": true, "--request": true,
		"-H": true, "--header": true,
		"-d": true, "--data": true,
		"--window-size": true,
		"--timeout":     true,
		"--color":       true,
	}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			out = append(out, args[i:]...)
			break
		}
		if takesValue[args[i]] {
			out = append(out, args[i])
			if i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
			continue
		}
		if args[i] == "--body" && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil && n >= 0 {
				out = append(out, fmt.Sprintf("--body=%d", n))
				i++
				continue
			}
		}
		out = append(out, args[i])
	}
	return out
}

func negotiateAndRun(urls []string, opts event.Options) ([]event.FrameEvent, error) {
	u0, err := url.Parse(urls[0])
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", urls[0], err)
	}

	scheme, host, _ := event.NormalizeURL(u0, "https")
	if scheme == "http" {
		return h1.Run(urls, opts)
	}

	tlsConn, alpn, connStart, err := event.DialTCPOrTLS(u0, "https", host, []string{"h2", "http/1.1"}, "", opts)
	if err != nil {
		return nil, err
	}

	opts.Conn = tlsConn
	opts.ConnStart = connStart

	if alpn == "h2" {
		return h2.Run(urls, opts)
	}
	return h1.Run(urls, opts)
}

func main() {
	var (
		flagH1         bool
		flagH2         bool
		flagH3         bool
		flagInsecure   bool
		flagMethod     string
		flagHeaders    []string
		flagData       string
		flagBodyLimit  = -1
		flagWindowSize uint32
		flagPing       bool
		flagTimeline   bool
		flagColor      string
		flagTimeout    time.Duration
	)

	pflag.CommandLine.SortFlags = false

	pflag.BoolVar(&flagH1, "h1", false, "Force HTTP/1.1 (or HTTP/1.0) protocol inspection")
	pflag.BoolVar(&flagH2, "h2", false, "Force HTTP/2 protocol inspection")
	pflag.BoolVar(&flagH3, "h3", false, "Force HTTP/3 (QUIC) protocol inspection")
	pflag.BoolVarP(&flagInsecure, "insecure", "k", false, "Skip TLS certificate verification")
	pflag.StringVarP(&flagMethod, "request", "X", "", "Specify HTTP request method to use (default GET, or POST with --data)")
	pflag.StringArrayVarP(&flagHeaders, "header", "H", nil, "Pass custom header(s) to server (e.g. -H 'Accept: application/json')")
	pflag.StringVarP(&flagData, "data", "d", "", "Send specified data in HTTP request body (use @file to read from file)")
	bodyFlag := pflag.CommandLine.VarPF(&bodyLimitValue{limit: &flagBodyLimit}, "body", "", "Display request/response body payloads up to N bytes (0 for full)")
	bodyFlag.NoOptDefVal = "200"
	pflag.Uint32Var(&flagWindowSize, "window-size", 4194304, "Initial stream receive window size in bytes (H2/H3)")
	pflag.BoolVar(&flagPing, "ping", false, "Send a PING frame and measure round-trip time (RTT) (H2)")
	pflag.BoolVar(&flagTimeline, "timeline", false, "Render an ASCII timeline chart")
	pflag.StringVar(&flagColor, "color", "auto", "Colorize output: auto, always, or never")
	pflag.DurationVar(&flagTimeout, "timeout", 10*time.Second, "Overall connection and request timeout")

	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <URL1> [URL2 ... URL_N]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		pflag.PrintDefaults()
	}

	os.Args = normalizeBodyArgs(os.Args)
	pflag.Parse()

	urls := pflag.Args()
	if len(urls) == 0 {
		pflag.Usage()
		os.Exit(1)
	}

	protoCount := 0
	if flagH1 {
		protoCount++
	}
	if flagH2 {
		protoCount++
	}
	if flagH3 {
		protoCount++
	}
	if protoCount > 1 {
		fmt.Fprintln(os.Stderr, "Error: cannot specify multiple protocol flags (--h1, --h2, --h3)")
		os.Exit(1)
	}

	if strings.HasPrefix(flagData, "@") && len(flagData) > 1 {
		filePath := flagData[1:]
		b, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to read data file %q: %v\n", filePath, err)
			os.Exit(1)
		}
		flagData = string(b)
	}

	for i, u := range urls {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			urls[i] = "https://" + u
		}
	}

	render.SetColorEnabled(render.ResolveColorMode(flagColor, os.Stdout))

	onInfo := func(msg string, elapsed time.Duration) {
		if !flagTimeline {
			fmt.Print(render.FormatInfo(msg, elapsed))
		}
	}

	onEvent := func(e event.FrameEvent) {
		if !flagTimeline {
			fmt.Print(render.FormatEvent(e))
		}
	}

	opts := event.Options{
		Method:     flagMethod,
		Data:       flagData,
		Headers:    flagHeaders,
		ShowBody:   flagBodyLimit >= 0,
		BodyLimit:  flagBodyLimit,
		WindowSize: flagWindowSize,
		Ping:       flagPing,
		Insecure:   flagInsecure,
		Timeout:    flagTimeout,
		OnEvent:    onEvent,
		OnInfo:     onInfo,
	}

	var events []event.FrameEvent
	var err error

	switch {
	case flagH1:
		events, err = h1.Run(urls, opts)
	case flagH2:
		events, err = h2.Run(urls, opts)
	case flagH3:
		events, err = h3.Run(urls, opts)
	default:
		events, err = negotiateAndRun(urls, opts)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if flagTimeline {
		render.RenderTimeline(os.Stdout, events)
	}
}
