# httpviz

`httpviz` is a command-line tool for inspecting HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) traffic at the frame and protocol level.

## Features

- **HTTP/1.1 (`--h1`)**: Raw request/status lines, headers, Keep-Alive reuse, and chunked transfer encoding boundaries.
- **HTTP/2 (`--h2`)**: Raw frame sequence (`MAGIC`, `SETTINGS`, `HEADERS`, `DATA`, `WINDOW_UPDATE`, `PING`, `RST_STREAM`, `GOAWAY`), HPACK compression ratios, static/dynamic table indexing, and flow-control window transitions.
- **HTTP/3 (`--h3`)**: QUIC packets (`QUIC_PACKET`) and inner frames (`STREAM`, `ACK`, `CRYPTO`, `HANDSHAKE_DONE`, etc.) alongside HTTP/3 frames via `quic-go` qlog tracing.
- **Connection timing**: DNS lookup, TCP connect, and TLS handshake duration with negotiated TLS version, cipher suite, and ALPN.
- **Timeline view (`--timeline`)**: ASCII chart showing how multiple streams are interleaved over a connection.
- **Capture file visualization (`-r, --read`)**: Offline visualization of HAR (`.har`) and PCAP/PCAPNG (`.pcap`, `.pcapng`) files in both tree and timeline views.

## Install

```bash
go install github.com/haccht/httpviz/cmd/httpviz@latest
```

Or build from source:

```bash
git clone https://github.com/haccht/httpviz.git
cd httpviz
go build -o bin/httpviz ./cmd/httpviz
```

## Usage

```text
Usage:
  httpviz [flags] <URL1> [URL2 ... URL_N]
  httpviz [flags] -r <file>

Flags:
  -r, --read string          Read and visualize traffic from a capture file (.har, .pcap, .pcapng)
      --h1                   Force HTTP/1.1 protocol inspection
      --h2                   Force HTTP/2 protocol inspection
      --h3                   Force HTTP/3 (QUIC) protocol inspection
  -k, --insecure             Skip TLS certificate verification
  -X, --request string       Specify HTTP request method to use (default GET, or POST with --data)
  -H, --header stringArray   Pass custom header(s) to server (e.g. -H 'Accept: application/json')
  -d, --data string          Send specified data in HTTP request body (use @file to read from file)
      --body int[=200]       Display request/response body payloads up to N bytes (0 for full)
      --window-size uint32   Initial stream receive window size in bytes (H2/H3) (default 4194304)
      --ping                 Send a PING frame and measure round-trip time (RTT) (H2)
      --timeline             Render an ASCII timeline chart
      --color string         Colorize output: auto, always, or never (default "auto")
      --timeout duration     Overall connection and request timeout (default 10s)
```

When no protocol flag (`--h1`, `--h2`, `--h3`) is specified, `httpviz` uses HTTP/1.1 for `http://` URLs and negotiates `h2` or `http/1.1` via TLS ALPN for `https://` URLs.

## Examples

### HTTP/2 (default for HTTPS)

```text
$ httpviz https://example.com/index.html
[ 0.001s] * DNS Lookup: example.com -> 93.184.215.14 (1.2ms)
[ 0.013s] * TCP Connected to 93.184.215.14:443 (11.8ms)
[ 0.029s] * TLS Handshake: TLSv1.3, Cipher: TLS_AES_128_GCM_SHA256 (16.2ms)
[ 0.029s] * Connected to 93.184.215.14:443 (TLSv1.3, ALPN: h2)
[ 0.029s] ──> MAGIC     (24B) "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
[ 0.029s] ──> [Stream 0] SETTINGS         (len=12)
             ├─ ENABLE_PUSH: 0
             └─ INITIAL_WINDOW_SIZE: 4194304 (4MB)
[ 0.030s] ──> [Stream 1] HEADERS          (len=31, flags=0x5 [END_HEADERS | END_STREAM])
             │  (HPACK: Compressed 31B -> Decompressed 246B, Ratio: 12%)
             ├─ :method: GET  [Static Index: 2]
             ├─ :path: /index.html  [Static Index: 5]
             ├─ :scheme: https  [Static Index: 7]
             ├─ :authority: example.com  [Literal, Indexed -> Dynamic Index: 62]
             ├─ user-agent: httpviz/0.1.0  [Literal, Indexed -> Dynamic Index: 63]
             └─ accept: */*  [Literal, Indexed -> Dynamic Index: 64]
[ 0.045s] <── [Stream 0] SETTINGS         (len=18)
             ├─ MAX_CONCURRENT_STREAMS: 100
             ├─ INITIAL_WINDOW_SIZE: 65535
             └─ MAX_FRAME_SIZE: 16384
[ 0.045s] ──> [Stream 0] SETTINGS         (len=0, flags=0x1 [ACK])
[ 0.046s] <── [Stream 0] SETTINGS         (len=0, flags=0x1 [ACK])
[ 0.052s] <── [Stream 1] HEADERS          (len=142, flags=0x4 [END_HEADERS])
             │  (HPACK: Compressed 142B -> Decompressed 210B, Ratio: 67%)
             ├─ :status: 200  [Static Index: 8]
             └─ content-type: text/html  [Literal, Indexed -> Dynamic Index: 62]
[ 0.053s] <── [Stream 1] DATA             (len=1256, flags=0x1 [END_STREAM])
             └─ [Conn Window: 65535 -> 64279] [Stream 1 Window: 4194304 -> 4193048]
```

### HTTP/1.1 (`--h1`)

```text
$ httpviz --h1 http://example.com/chunked
[ 0.001s] * DNS Lookup: example.com -> 93.184.215.14 (1.1ms)
[ 0.015s] * Connected to 93.184.215.14:80 (TCP, 14.0ms)
[ 0.015s] ──> REQUEST_LINE     "GET /chunked HTTP/1.1"
[ 0.015s] ──> [Stream 0] HEADERS          (len=74)
             ├─ Host: example.com
             ├─ User-Agent: httpviz/0.1.0
             └─ Connection: keep-alive
[ 0.038s] <── STATUS_LINE      "HTTP/1.1 200 OK"
[ 0.038s] <── [Stream 0] HEADERS          (len=118)
             ├─ Content-Type: text/plain
             └─ Transfer-Encoding: chunked
[ 0.040s] <── CHUNK            (size=19B, chunk #1)
[ 0.041s] <── CHUNK            (size=0B, chunk #2, [FIN])
[ 0.041s] * Connection kept alive
```

### HTTP/3 (`--h3`)

```text
$ httpviz --h3 https://example.com/index.html
[ 0.001s] * DNS Lookup: example.com -> 93.184.215.14 (1.1ms)
[ 0.001s] * Connected to example.com:443 (QUIC, ALPN: h3)
[ 0.002s] ──> QUIC_PACKET      (type=initial, num=0)
             └─ CRYPTO (len=295)
                └─ offset=0
[ 0.018s] <── QUIC_PACKET      (type=initial, num=0)
             ├─ ACK
             │  └─ ack_delay=0s
             └─ CRYPTO (len=90)
                └─ offset=0
[ 0.020s] ──> [Stream 0] HEADERS          (len=48)
             ├─ :authority: example.com
             ├─ :method: GET
             ├─ :path: /index.html
             ├─ :scheme: https
             └─ user-agent: httpviz/0.1.0
[ 0.035s] <── [Stream 0] HEADERS          (len=34)
             ├─ :status: 200
             └─ content-type: text/html
[ 0.036s] <── [Stream 0] DATA             (len=1256)
```

### Multiplexing Timeline (`--timeline`)

```text
$ httpviz --timeline https://example.com/a.js https://example.com/b.css
Time (ms) │ 0         10        20        30        40        50        60
──────────┼───────────────────────────────────────────────────────────────
Stream 0  │ [S]───────[s][S*]
Stream 1  │      [H]────────────[h][d*] (200 OK, 1.2KB)
Stream 3  │       [H]────────────────[h]──[d*] (200 OK, 4.5KB)
──────────┴───────────────────────────────────────────────────────────────
Legend:
  Upper = Sent (Client -> Server), Lower = Recv (Server -> Client)
  [S]/[s] SETTINGS   [W]/[w] WINDOW_UPDATE   [H]/[h] HEADERS
  [D]/[d] DATA       [G]/[g] GOAWAY          * = END_STREAM / ACK
```

### Capture Files (`-r, --read`)

Visualize browser-exported `.har` files or packet captures (`.pcap`, `.pcapng`):

```text
$ httpviz -r trace.har --timeline
$ httpviz -r capture.pcap --body
```

## License

[MIT License](./LICENSE)
