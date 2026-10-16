package pcap

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"github.com/haccht/httpviz/pkg/render"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type synthPacket struct {
	offsetMs int
	srcIP    string
	srcPort  uint16
	dstIP    string
	dstPort  uint16
	seq      uint32
	ack      uint32
	flags    uint8
	payload  []byte
}

func buildEthernetIPv4TCP(p synthPacket) []byte {
	var buf bytes.Buffer
	// 14-byte Ethernet header (dst MAC 6B, src MAC 6B, EtherType 0x0800)
	buf.Write(make([]byte, 12))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0800))

	// 20-byte IPv4 header
	totalLen := uint16(20 + 20 + len(p.payload))
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], totalLen)
	ipHdr[8] = 64 // TTL
	ipHdr[9] = 6  // Protocol TCP
	copy(ipHdr[12:16], net.ParseIP(p.srcIP).To4())
	copy(ipHdr[16:20], net.ParseIP(p.dstIP).To4())
	buf.Write(ipHdr)

	// 20-byte TCP header
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], p.srcPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], p.dstPort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], p.seq)
	binary.BigEndian.PutUint32(tcpHdr[8:12], p.ack)
	tcpHdr[12] = 5 << 4 // Data offset 5 (20 bytes)
	tcpHdr[13] = p.flags
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	buf.Write(tcpHdr)

	buf.Write(p.payload)
	return buf.Bytes()
}

func buildClassicPCAP(pkts []synthPacket) []byte {
	var buf bytes.Buffer
	// Global header (24 bytes, Little Endian microsecond)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(linkTypeEthernet))

	baseSec := uint32(1700000000)
	for _, p := range pkts {
		raw := buildEthernetIPv4TCP(p)
		tsSec := baseSec + uint32(p.offsetMs/1000)
		tsUsec := uint32((p.offsetMs % 1000) * 1000)
		_ = binary.Write(&buf, binary.LittleEndian, tsSec)
		_ = binary.Write(&buf, binary.LittleEndian, tsUsec)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(raw)))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(raw)))
		buf.Write(raw)
	}
	return buf.Bytes()
}

func buildPCAPNG(pkts []synthPacket) []byte {
	var buf bytes.Buffer
	// 1. Section Header Block (SHB) - 28 bytes
	_ = binary.Write(&buf, binary.LittleEndian, uint32(pcapngMagicSHB))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(28))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x1a2b3c4d)) // BOM
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, int64(-1))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(28))

	// 2. Interface Description Block (IDB) - 20 bytes
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000001))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(20))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(linkTypeEthernet))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(20))

	// 3. Enhanced Packet Blocks (EPB)
	baseMicro := uint64(1700000000) * 1_000_000
	for _, p := range pkts {
		raw := buildEthernetIPv4TCP(p)
		pad := (4 - (len(raw) % 4)) % 4
		blockLen := uint32(32 + len(raw) + pad)
		ts := baseMicro + uint64(p.offsetMs)*1000
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000006))
		_ = binary.Write(&buf, binary.LittleEndian, blockLen)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // Interface ID 0
		_ = binary.Write(&buf, binary.LittleEndian, uint32(ts>>32))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(ts&0xffffffff))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(raw)))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(raw)))
		buf.Write(raw)
		if pad > 0 {
			buf.Write(make([]byte, pad))
		}
		_ = binary.Write(&buf, binary.LittleEndian, blockLen)
	}
	return buf.Bytes()
}

func TestPCAP_HTTP1_Chunked(t *testing.T) {
	reqPayload := []byte("GET /chunked HTTP/1.1\r\nHost: example.com\r\nUser-Agent: httpviz/test\r\n\r\n")
	respPayload := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")

	pkts := []synthPacket{
		{offsetMs: 0, srcIP: "10.0.0.1", srcPort: 50000, dstIP: "93.184.215.14", dstPort: 80, seq: 100, flags: tcpFlagSYN},
		{offsetMs: 5, srcIP: "93.184.215.14", srcPort: 80, dstIP: "10.0.0.1", dstPort: 50000, seq: 200, ack: 101, flags: tcpFlagSYN | tcpFlagACK},
		{offsetMs: 10, srcIP: "10.0.0.1", srcPort: 50000, dstIP: "93.184.215.14", dstPort: 80, seq: 101, ack: 201, flags: tcpFlagACK},
		{offsetMs: 12, srcIP: "10.0.0.1", srcPort: 50000, dstIP: "93.184.215.14", dstPort: 80, seq: 101, ack: 201, flags: tcpFlagACK, payload: reqPayload},
		{offsetMs: 25, srcIP: "93.184.215.14", srcPort: 80, dstIP: "10.0.0.1", dstPort: 50000, seq: 201, ack: 101 + uint32(len(reqPayload)), flags: tcpFlagACK, payload: respPayload},
	}

	pcapBytes := buildClassicPCAP(pkts)
	var infos []string
	events, err := Run(bytes.NewReader(pcapBytes), event.Options{
		ShowBody:  true,
		BodyLimit: 200,
		OnInfo: func(msg string, _ time.Duration) {
			infos = append(infos, msg)
		},
	})
	if err != nil {
		t.Fatalf("pcap.Run failed: %v", err)
	}

	infoJoined := strings.Join(infos, "\n")
	if !strings.Contains(infoJoined, "* Connected to 93.184.215.14:80 (TCP, 10.0ms)") {
		t.Errorf("expected TCP connected info (10.0ms), got:\n%s", infoJoined)
	}

	var out strings.Builder
	render.RenderTree(&out, events)
	tree := out.String()
	if !strings.Contains(tree, `"GET /chunked HTTP/1.1"`) || !strings.Contains(tree, `"HTTP/1.1 200 OK"`) {
		t.Errorf("expected REQUEST_LINE and STATUS_LINE in tree, got:\n%s", tree)
	}
	if !strings.Contains(tree, "CHUNK") || !strings.Contains(tree, "Payload: hello") {
		t.Errorf("expected CHUNK with Payload: hello in tree, got:\n%s", tree)
	}
}

func TestPCAP_H2C_MultiplexingAndPing(t *testing.T) {
	var clientBuf bytes.Buffer
	clientBuf.WriteString(http2.ClientPreface)
	cFramer := http2.NewFramer(&clientBuf, nil)
	_ = cFramer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4194304})

	var hpackBuf bytes.Buffer
	enc := hpack.NewEncoder(&hpackBuf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/index.html"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "http"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "example.com"})
	_ = cFramer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hpackBuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	})
	_ = cFramer.WritePing(false, [8]byte{'h', 't', 't', 'p', 'v', 'i', 'z', '!'})

	var serverBuf bytes.Buffer
	sFramer := http2.NewFramer(&serverBuf, nil)
	_ = sFramer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
	_ = sFramer.WriteSettingsAck()

	hpackBuf.Reset()
	sEnc := hpack.NewEncoder(&hpackBuf)
	_ = sEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = sEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
	_ = sFramer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hpackBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
	_ = sFramer.WriteData(1, true, []byte("h2c response payload"))
	_ = sFramer.WritePing(true, [8]byte{'h', 't', 't', 'p', 'v', 'i', 'z', '!'})

	pkts := []synthPacket{
		{offsetMs: 0, srcIP: "127.0.0.1", srcPort: 51000, dstIP: "127.0.0.1", dstPort: 8080, seq: 1, flags: tcpFlagSYN},
		{offsetMs: 2, srcIP: "127.0.0.1", srcPort: 8080, dstIP: "127.0.0.1", dstPort: 51000, seq: 1, ack: 2, flags: tcpFlagSYN | tcpFlagACK},
		{offsetMs: 4, srcIP: "127.0.0.1", srcPort: 51000, dstIP: "127.0.0.1", dstPort: 8080, seq: 2, ack: 2, flags: tcpFlagACK},
		{offsetMs: 10, srcIP: "127.0.0.1", srcPort: 51000, dstIP: "127.0.0.1", dstPort: 8080, seq: 2, ack: 2, flags: tcpFlagACK, payload: clientBuf.Bytes()},
		{offsetMs: 25, srcIP: "127.0.0.1", srcPort: 8080, dstIP: "127.0.0.1", dstPort: 51000, seq: 2, ack: 2 + uint32(clientBuf.Len()), flags: tcpFlagACK, payload: serverBuf.Bytes()},
	}

	pcapngBytes := buildPCAPNG(pkts)
	events, err := Run(bytes.NewReader(pcapngBytes), event.Options{
		ShowBody:  true,
		BodyLimit: 200,
	})
	if err != nil {
		t.Fatalf("pcap.Run (PCAPNG h2c) failed: %v", err)
	}

	var out strings.Builder
	render.RenderTree(&out, events)
	tree := out.String()
	if !strings.Contains(tree, "MAGIC") || !strings.Contains(tree, "SETTINGS") || !strings.Contains(tree, "Static Index: 2") {
		t.Errorf("expected MAGIC, SETTINGS, and Static Index: 2 in h2c tree output, got:\n%s", tree)
	}
	if !strings.Contains(tree, "h2c response payload") {
		t.Errorf("expected h2c response payload in tree output, got:\n%s", tree)
	}
	if !strings.Contains(tree, "RTT: 15.00ms") {
		t.Errorf("expected PING RTT: 15.00ms in tree output, got:\n%s", tree)
	}
}

func TestPCAP_TLSHandshakeInfo(t *testing.T) {
	// Construct minimal TLS ClientHello with ALPN "h2" and ServerHello with TLS 1.3 + TLS_AES_128_GCM_SHA256 (0x1301)
	clientHelloBody := make([]byte, 0, 64)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)       // Legacy Version TLS 1.2
	clientHelloBody = append(clientHelloBody, make([]byte, 32)...) // Random
	clientHelloBody = append(clientHelloBody, 0x00)             // Session ID len 0
	clientHelloBody = append(clientHelloBody, 0x00, 0x02, 0x13, 0x01) // CipherSuites: TLS_AES_128_GCM_SHA256
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)       // Compression methods: null
	// Extensions: ALPN (0x0010) -> "h2"
	alpnExt := []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'}
	clientHelloBody = append(clientHelloBody, 0x00, byte(len(alpnExt)))
	clientHelloBody = append(clientHelloBody, alpnExt...)

	var clientRecord []byte
	clientRecord = append(clientRecord, 0x16, 0x03, 0x01, 0x00, byte(len(clientHelloBody)+4))
	clientRecord = append(clientRecord, 0x01, 0x00, 0x00, byte(len(clientHelloBody)))
	clientRecord = append(clientRecord, clientHelloBody...)

	serverHelloBody := make([]byte, 0, 64)
	serverHelloBody = append(serverHelloBody, 0x03, 0x03)       // Legacy Version TLS 1.2
	serverHelloBody = append(serverHelloBody, make([]byte, 32)...) // Random
	serverHelloBody = append(serverHelloBody, 0x00)             // Session ID len 0
	serverHelloBody = append(serverHelloBody, 0x13, 0x01)       // CipherSuite: TLS_AES_128_GCM_SHA256
	serverHelloBody = append(serverHelloBody, 0x00)             // Compression method: null
	// Extensions: supported_versions (0x002b) -> TLS 1.3 (0x0304)
	supVerExt := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	serverHelloBody = append(serverHelloBody, 0x00, byte(len(supVerExt)))
	serverHelloBody = append(serverHelloBody, supVerExt...)

	var serverRecord []byte
	serverRecord = append(serverRecord, 0x16, 0x03, 0x03, 0x00, byte(len(serverHelloBody)+4))
	serverRecord = append(serverRecord, 0x02, 0x00, 0x00, byte(len(serverHelloBody)))
	serverRecord = append(serverRecord, serverHelloBody...)

	pkts := []synthPacket{
		{offsetMs: 0, srcIP: "10.0.0.2", srcPort: 52000, dstIP: "93.184.215.14", dstPort: 443, seq: 10, flags: tcpFlagSYN},
		{offsetMs: 6, srcIP: "93.184.215.14", srcPort: 443, dstIP: "10.0.0.2", dstPort: 52000, seq: 20, ack: 11, flags: tcpFlagSYN | tcpFlagACK},
		{offsetMs: 12, srcIP: "10.0.0.2", srcPort: 52000, dstIP: "93.184.215.14", dstPort: 443, seq: 11, ack: 21, flags: tcpFlagACK},
		{offsetMs: 13, srcIP: "10.0.0.2", srcPort: 52000, dstIP: "93.184.215.14", dstPort: 443, seq: 11, ack: 21, flags: tcpFlagACK, payload: clientRecord},
		{offsetMs: 28, srcIP: "93.184.215.14", srcPort: 443, dstIP: "10.0.0.2", dstPort: 52000, seq: 21, ack: 11 + uint32(len(clientRecord)), flags: tcpFlagACK, payload: serverRecord},
	}

	var infos []string
	_, err := Run(bytes.NewReader(buildClassicPCAP(pkts)), event.Options{
		OnInfo: func(msg string, _ time.Duration) {
			infos = append(infos, msg)
		},
	})
	if err != nil {
		t.Fatalf("pcap.Run (TLS) failed: %v", err)
	}

	infoJoined := strings.Join(infos, "\n")
	if !strings.Contains(infoJoined, "* TCP Connected to 93.184.215.14:443 (12.0ms)") {
		t.Errorf("expected TCP Connected info, got:\n%s", infoJoined)
	}
	if !strings.Contains(infoJoined, "* TLS Handshake: TLS 1.3, Cipher: TLS_AES_128_GCM_SHA256 (15.0ms)") &&
		!strings.Contains(infoJoined, "* TLS Handshake: TLSv1.3, Cipher: TLS_AES_128_GCM_SHA256 (15.0ms)") {
		t.Errorf("expected TLS Handshake info, got:\n%s", infoJoined)
	}
	if !strings.Contains(infoJoined, "ALPN: h2") {
		t.Errorf("expected ALPN: h2 in TLS info, got:\n%s", infoJoined)
	}
}
