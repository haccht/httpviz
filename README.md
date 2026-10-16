# httpviz

**httpviz** is a low-level HTTP/1.x, HTTP/2, and HTTP/3 (QUIC) frame and protocol visualizer written in Go. 

Unlike standard tools like `curl -v` that abstract away the underlying transport framing, `httpviz` inspects and visualizes raw network bytes, DNS/TCP/TLS handshakes, request/response headers, chunked transfer encodings, multiplexed frames, HPACK/QPACK compression, and flow-control window transitions right in your terminal.

---

## Features

- **Multi-Protocol Inspection (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3)**: Automatically detects protocol versions or forces specific layers to inspect raw bytes, request/response lines, and framed data.
- **Connection & Handshake Timing**: Measures and displays DNS resolution, TCP connection, and TLS handshake phases (including negotiated TLS version, cipher suite, and ALPN).
- **ANSI Color Highlighting (`--color`)**: Color-codes outbound/inbound directions, frame types, HTTP status codes, and distinct stream IDs in both Tree and Timeline views (auto-detected on TTY, respects `NO_COLOR`).
- **HTTP/1.x Raw Stream & Chunking View**: Visualizes raw sockets, CRLF boundaries, header ordering, Keep-Alive connection states, and Chunked Transfer-Encoding chunks.
- **Low-Level HTTP/2 Frame Inspection**: Bypasses standard clients to capture raw `MAGIC`, `SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`, `RST_STREAM`, and `GOAWAY` frames.
- **HPACK Compression Insights**: Displays compressed vs. decompressed header sizes, compression ratios, and indexing states (for both sent and received headers).
- **Flow Control Window Tracking**: Tracks real-time transitions of connection-level and stream-level flow control windows for HTTP/2 and HTTP/3.
- **Multiplexing ASCII Timeline (`--timeline`)**: Visualizes how multiple concurrent streams are interleaved over a single connection using an ASCII Gantt-style chart.
- **HTTP/3 & QUIC Packet Hierarchy (`--h3`)**: Hooks into `quic-go` connection tracers to show how HTTP/3 frames are encapsulated inside QUIC `STREAM` frames and 1-RTT packets.

---

## Installation

### Build from source

Requires Go 1.22 or later.

```bash
git clone https://github.com/haccht/httpviz.git
cd httpviz
go build -o bin/httpviz ./cmd/httpviz
```

Or install directly via `go install`:

```bash
go install github.com/haccht/httpviz/cmd/httpviz@latest
```

---

## Usage

```bash
httpviz [flags] <URL1> [URL2 ... URL_N]
```

### Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--h1` | Force HTTP/1.1 (or HTTP/1.0) protocol inspection | `false` |
| `--h2` | Force HTTP/2 protocol inspection | `false` |
| `--h3` | Force HTTP/3 (QUIC) protocol inspection | `false` |
| `-k`, `--insecure` | Skip TLS certificate verification (useful for local testing) | `false` |
| `-X`, `--request` | Specify HTTP request method to use (`GET`, `POST`, `PUT`, etc.) | `GET` (`POST` with `-d`) |
| `-H`, `--header` | Pass custom header(s) to server (repeatable, e.g. `-H 'X-Test: 1'`) | `[]` |
| `-d`, `--data` | Send specified data in HTTP request body (use `@file` to read from file) | `""` |
| `--body [N]` | Display request/response body payloads up to `N` bytes (`0` for full) | `200` (when `--body` set) |
| `--window-size` | Initial stream receive window size in bytes (H2/H3) | `4194304` (4MB) |
| `--ping` | Send a `PING` frame and measure round-trip time (RTT) (H2) | `false` |
| `--timeline` | Render an ASCII timeline chart | `false` |
| `--color` | Colorize output: `auto`, `always`, or `never` | `auto` |
| `--timeout` | Overall connection and request timeout | `10s` |

> **Note:** When none of `--h1`, `--h2`, or `--h3` is specified, `httpviz` negotiates the protocol with the server via TLS ALPN (`h2`, `http/1.1`) for `https://` URLs (or uses HTTP/1.1 for `http://` URLs).

---

## Output Examples

### 1. HTTP/1.1 Raw Stream View (`--h1`)

Inspects raw socket bytes, request lines, headers, and chunked transfer decoding boundaries.

```text
$ httpviz --h1 http://example.com/api/data

[ 0.001s] * DNS Lookup: example.com -> 93.184.215.14 (1.2ms)
[ 0.015s] * Connected to 93.184.215.14:80 (TCP, 14.1ms)
[ 0.015s] ──> REQUEST_LINE     "GET /api/data HTTP/1.1"
[ 0.015s] ──> [Stream 0] HEADERS          (len=74)
             ├─ Host: example.com
             ├─ User-Agent: httpviz/0.1.0
             └─ Connection: keep-alive
[ 0.038s] <── STATUS_LINE      "HTTP/1.1 200 OK"
[ 0.038s] <── [Stream 0] HEADERS          (len=156)
             ├─ Content-Type: application/json
             ├─ Transfer-Encoding: chunked
             └─ Connection: keep-alive
[ 0.040s] <── CHUNK            (size=512B, chunk #1)
[ 0.041s] <── CHUNK            (size=0B, chunk #2, [FIN])
[ 0.041s] * Connection kept alive (Keep-Alive: timeout=5, max=100)
```

### 2. HTTP/2 Stream Tree View (Default)

Inspects DNS/TCP/TLS handshakes, the chronological sequence of frames, HPACK compression ratios, and flow control window consumption.

```text
$ httpviz https://example.com/index.html

[ 0.001s] * DNS Lookup: example.com -> 93.184.215.14 (1.1ms)
[ 0.013s] * TCP Connected to 93.184.215.14:443 (11.8ms)
[ 0.029s] * TLS Handshake: TLSv1.3, Cipher: TLS_AES_128_GCM_SHA256 (16.2ms)
[ 0.029s] * Connected to 93.184.215.14:443 (TLSv1.3, ALPN: h2)
[ 0.029s] ──> MAGIC     (24B) "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
[ 0.029s] ──> [Stream 0] SETTINGS         (len=12)
             ├─ ENABLE_PUSH: 0
             └─ INITIAL_WINDOW_SIZE: 4194304 (4MB)
[ 0.030s] ──> [Stream 1] HEADERS          (len=31, flags=0x5 [END_HEADERS | END_STREAM])
             │  (HPACK: Compressed 31B -> Decompressed 118B, Ratio: 26%)
             ├─ :method: GET  [Static Index: 2]
             └─ :path: /index.html  [Literal, Indexed -> Dynamic Index: 62]
[ 0.052s] <── [Stream 1] HEADERS          (len=142, flags=0x4 [END_HEADERS])
             ├─ :status: 200  [Static Index: 8]
             └─ content-type: text/html  [Literal, Indexed -> Dynamic Index: 62]
[ 0.053s] <── [Stream 1] DATA             (len=1000)
             └─ [Conn Window: 65535 -> 64535] [Stream 1 Window: 4194304 -> 4193304]
```

### 3. Multiplexing Timeline View (`--timeline`)

Pass multiple URLs with `--timeline` to observe how streams are multiplexed on a single connection.

```text
$ httpviz --timeline https://example.com/a.js https://example.com/b.css https://example.com/c.png

Time (ms) │ 0         10        20        30        40        50        60
──────────┼───────────────────────────────────────────────────────────────
Stream 0  │ [S]───[W]─[s][S*]───────────────────────[W]────────────────[G]
Stream 1  │   [H]─────────[h][d][d*] (200 OK, 1.2KB)
Stream 3  │    [H]──────────[h][d][d][d*] (200 OK, 4.5KB)
Stream 5  │     [H]───────────[h][d][d][d]──────────────────────[d][d*]
──────────┴───────────────────────────────────────────────────────────────
Legend:
  Upper = Sent (Client -> Server), Lower = Recv (Server -> Client)
  [S]/[s] SETTINGS   [W]/[w] WINDOW_UPDATE   [H]/[h] HEADERS
  [D]/[d] DATA       [G]/[g] GOAWAY          * = END_STREAM / ACK
```

---

## Project Structure

```text
.
├── cmd/httpviz/main.go           # CLI entrypoint & flag parsing
├── pkg/
│   ├── event/
│   │   ├── event.go              # FrameEvent definitions, FrameType constants & shared Options
│   │   └── dial.go               # DNS / TCP / TLS handshake phase timing & connection dialer
│   ├── h1/client.go              # Raw TCP socket & HTTP/1.x stream/chunk parser
│   ├── h2/client.go              # Low-level HTTP/2 Framer client & HPACK decoder
│   ├── h3/client.go              # HTTP/3 client with quic-go ConnectionTracer hooks
│   └── render/
│       ├── color.go              # ANSI color palette & TTY / NO_COLOR detection
│       ├── tree.go               # Indented tree formatter
│       └── timeline.go           # ASCII multiplexing timeline renderer
└── internal/testserver/server.go # Self-contained local h1/h2/h3 server for E2E tests
```

## License

[MIT License](./LICENSE)
