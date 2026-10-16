package pcap

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/haccht/httpviz/pkg/event"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	pcapMagicMicroBE = 0xa1b2c3d4
	pcapMagicMicroLE = 0xd4c3b2a1
	pcapMagicNanoBE  = 0xa1b23c4d
	pcapMagicNanoLE  = 0x4d3cb2a1
	pcapngMagicSHB   = 0x0a0d0d0a

	linkTypeNull     = 0
	linkTypeEthernet = 1
	linkTypeRawIP1   = 12
	linkTypeRawIP2   = 101
	linkTypeLinuxSLL = 113
	linkTypeRawIPv4  = 228
	linkTypeRawIPv6  = 229
	linkTypeSLL2     = 276

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

type rawPacket struct {
	ts       time.Time
	linkType uint32
	data     []byte
}

type tcpPacket struct {
	ts      time.Time
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
	seq     uint32
	ack     uint32
	flags   uint8
	payload []byte
}

type timestampedChunk struct {
	ts     time.Time
	seq    uint32
	data   []byte
	offset int // byte offset in reassembled stream
}

type tcpStream struct {
	chunks []timestampedChunk
	buf    bytes.Buffer
	next   uint32
	hasSeq bool
}

func (s *tcpStream) appendSegment(ts time.Time, seq uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}
	if !s.hasSeq {
		s.hasSeq = true
		s.next = seq
	}
	// Handle retransmissions or overlapping segments
	diff := int32(seq - s.next)
	if diff < 0 {
		trim := int(-diff)
		if trim >= len(payload) {
			return
		}
		payload = payload[trim:]
		seq += uint32(trim)
	}
	offset := s.buf.Len()
	cp := append([]byte(nil), payload...)
	s.buf.Write(cp)
	s.chunks = append(s.chunks, timestampedChunk{
		ts:     ts,
		seq:    seq,
		data:   cp,
		offset: offset,
	})
	s.next = seq + uint32(len(cp))
}

func (s *tcpStream) timeAtOffset(byteOffset int, fallback time.Time) time.Time {
	for i := len(s.chunks) - 1; i >= 0; i-- {
		if byteOffset >= s.chunks[i].offset {
			return s.chunks[i].ts
		}
	}
	if len(s.chunks) > 0 {
		return s.chunks[0].ts
	}
	return fallback
}

type endpoint struct {
	ip   string
	port uint16
}

func (e endpoint) String() string {
	return net.JoinHostPort(e.ip, strconv.Itoa(int(e.port)))
}

type tcpConnection struct {
	client       endpoint
	server       endpoint
	roleResolved bool
	synTime      time.Time
	synAckTime   time.Time
	ackTime      time.Time
	firstTime    time.Time
	c2s          tcpStream
	s2c          tcpStream
}

func readAllPackets(r io.Reader) ([]rawPacket, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read capture data: %w", err)
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("capture file too short (%d bytes)", len(data))
	}

	magicBE := binary.BigEndian.Uint32(data[0:4])
	if magicBE == pcapngMagicSHB {
		return parsePCAPNG(data)
	}
	return parseClassicPCAP(data, magicBE)
}

func parseClassicPCAP(data []byte, magicBE uint32) ([]rawPacket, error) {
	var bo binary.ByteOrder
	var nano bool

	switch magicBE {
	case pcapMagicMicroBE:
		bo = binary.BigEndian
		nano = false
	case pcapMagicMicroLE:
		bo = binary.LittleEndian
		nano = false
	case pcapMagicNanoBE:
		bo = binary.BigEndian
		nano = true
	case pcapMagicNanoLE:
		bo = binary.LittleEndian
		nano = true
	default:
		return nil, fmt.Errorf("unrecognized PCAP magic 0x%08x", magicBE)
	}

	linkType := bo.Uint32(data[20:24])
	pos := 24
	var pkts []rawPacket

	for pos+16 <= len(data) {
		tsSec := bo.Uint32(data[pos : pos+4])
		tsSub := bo.Uint32(data[pos+4 : pos+8])
		inclLen := bo.Uint32(data[pos+8 : pos+12])
		pos += 16

		if pos+int(inclLen) > len(data) {
			break
		}
		pktData := data[pos : pos+int(inclLen)]
		pos += int(inclLen)

		var nsec int64
		if nano {
			nsec = int64(tsSub)
		} else {
			nsec = int64(tsSub) * 1000
		}
		pkts = append(pkts, rawPacket{
			ts:       time.Unix(int64(tsSec), nsec),
			linkType: linkType,
			data:     pktData,
		})
	}
	return pkts, nil
}

func parsePCAPNG(data []byte) ([]rawPacket, error) {
	var bo binary.ByteOrder = binary.LittleEndian
	var ifLinkTypes []uint32
	var pkts []rawPacket

	pos := 0
	for pos+12 <= len(data) {
		blockType := bo.Uint32(data[pos : pos+4])
		if blockType == pcapngMagicSHB {
			if pos+12 <= len(data) {
				bom := binary.BigEndian.Uint32(data[pos+8 : pos+12])
				if bom == 0x1a2b3c4d {
					bo = binary.BigEndian
				} else if bom == 0x4d3c2b1a {
					bo = binary.LittleEndian
				}
			}
			blockLen := int(bo.Uint32(data[pos+4 : pos+8]))
			if blockLen < 12 || pos+blockLen > len(data) {
				break
			}
			ifLinkTypes = nil
			pos += blockLen
			continue
		}

		blockLen := int(bo.Uint32(data[pos+4 : pos+8]))
		if blockLen < 12 || pos+blockLen > len(data) {
			break
		}
		body := data[pos+8 : pos+blockLen-4]

		switch blockType {
		case 0x00000001: // Interface Description Block (IDB)
			if len(body) >= 8 {
				lt := uint32(bo.Uint16(body[0:2]))
				ifLinkTypes = append(ifLinkTypes, lt)
			}
		case 0x00000006: // Enhanced Packet Block (EPB)
			if len(body) >= 20 {
				ifID := int(bo.Uint32(body[0:4]))
				tsHigh := uint64(bo.Uint32(body[4:8]))
				tsLow := uint64(bo.Uint32(body[8:12]))
				capLen := int(bo.Uint32(body[12:16]))
				if 20+capLen <= len(body) {
					tsMicro := (tsHigh << 32) | tsLow
					sec := int64(tsMicro / 1_000_000)
					nsec := int64((tsMicro % 1_000_000) * 1000)
					lt := uint32(linkTypeEthernet)
					if ifID >= 0 && ifID < len(ifLinkTypes) {
						lt = ifLinkTypes[ifID]
					}
					pkts = append(pkts, rawPacket{
						ts:       time.Unix(sec, nsec),
						linkType: lt,
						data:     body[20 : 20+capLen],
					})
				}
			}
		}

		pos += blockLen
	}
	return pkts, nil
}

func decodeTCPPacket(raw rawPacket) (*tcpPacket, bool) {
	b := raw.data
	switch raw.linkType {
	case linkTypeNull:
		if len(b) < 4 {
			return nil, false
		}
		b = b[4:]
	case linkTypeEthernet:
		if len(b) < 14 {
			return nil, false
		}
		etherType := binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		if etherType == 0x8100 || etherType == 0x88a8 { // 802.1Q VLAN
			if len(b) < 4 {
				return nil, false
			}
			etherType = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
		if etherType != 0x0800 && etherType != 0x86dd {
			return nil, false
		}
	case linkTypeLinuxSLL:
		if len(b) < 16 {
			return nil, false
		}
		b = b[16:]
	case linkTypeSLL2:
		if len(b) < 20 {
			return nil, false
		}
		b = b[20:]
	case linkTypeRawIP1, linkTypeRawIP2, linkTypeRawIPv4, linkTypeRawIPv6:
		// Raw IP starts immediately
	default:
		return nil, false
	}

	if len(b) < 20 {
		return nil, false
	}

	version := b[0] >> 4
	var srcIP, dstIP string
	var tcpBytes []byte

	switch version {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return nil, false
		}
		totalLen := int(binary.BigEndian.Uint16(b[2:4]))
		if totalLen >= ihl && totalLen <= len(b) {
			b = b[:totalLen]
		}
		if b[9] != 6 { // Not TCP
			return nil, false
		}
		srcIP = net.IP(b[12:16]).String()
		dstIP = net.IP(b[16:20]).String()
		tcpBytes = b[ihl:]
	case 6:
		if len(b) < 40 {
			return nil, false
		}
		payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
		if 40+payloadLen <= len(b) {
			b = b[:40+payloadLen]
		}
		if b[6] != 6 { // NextHeader != TCP
			return nil, false
		}
		srcIP = net.IP(b[8:24]).String()
		dstIP = net.IP(b[24:40]).String()
		tcpBytes = b[40:]
	default:
		return nil, false
	}

	if len(tcpBytes) < 20 {
		return nil, false
	}
	srcPort := binary.BigEndian.Uint16(tcpBytes[0:2])
	dstPort := binary.BigEndian.Uint16(tcpBytes[2:4])
	seq := binary.BigEndian.Uint32(tcpBytes[4:8])
	ack := binary.BigEndian.Uint32(tcpBytes[8:12])
	dataOffset := int(tcpBytes[12]>>4) * 4
	flags := tcpBytes[13]
	if dataOffset < 20 || len(tcpBytes) < dataOffset {
		return nil, false
	}

	return &tcpPacket{
		ts:      raw.ts,
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
		seq:     seq,
		ack:     ack,
		flags:   flags,
		payload: tcpBytes[dataOffset:],
	}, true
}

func connKey(a, b endpoint) string {
	sa := a.String()
	sb := b.String()
	if sa < sb {
		return sa + "<->" + sb
	}
	return sb + "<->" + sa
}

func looksLikeClientPayload(b []byte) bool {
	if strings.HasPrefix(string(b), http2.ClientPreface) {
		return true
	}
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
	for _, m := range methods {
		if strings.HasPrefix(string(b), m) {
			return true
		}
	}
	// TLS ClientHello record: ContentType 0x16, Version 0x0301..0x0303, HandshakeType 0x01
	if len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 {
		return true
	}
	return false
}

type timedRecord struct {
	isInfo bool
	info   string
	ts     time.Duration
	order  int
	ev     event.FrameEvent
}

// Run reads a PCAP or PCAPNG stream, reassembles TCP connections, and emits FrameEvents.
func Run(r io.Reader, opts event.Options) ([]event.FrameEvent, error) {
	rawPkts, err := readAllPackets(r)
	if err != nil {
		return nil, err
	}
	if len(rawPkts) == 0 {
		return nil, fmt.Errorf("capture file contains no packets")
	}

	var baseTime time.Time
	var connOrder []string
	conns := make(map[string]*tcpConnection)

	for _, rp := range rawPkts {
		tp, ok := decodeTCPPacket(rp)
		if !ok {
			continue
		}
		if baseTime.IsZero() || tp.ts.Before(baseTime) {
			baseTime = tp.ts
		}

		src := endpoint{ip: tp.srcIP, port: tp.srcPort}
		dst := endpoint{ip: tp.dstIP, port: tp.dstPort}
		key := connKey(src, dst)

		c, exists := conns[key]
		if !exists {
			c = &tcpConnection{
				client:    src,
				server:    dst,
				firstTime: tp.ts,
			}
			conns[key] = c
			connOrder = append(connOrder, key)
		}

		// Determine client vs server role
		if !c.roleResolved {
			if (tp.flags&tcpFlagSYN) != 0 && (tp.flags&tcpFlagACK) == 0 {
				c.client = src
				c.server = dst
				c.roleResolved = true
			} else if (tp.flags&tcpFlagSYN) != 0 && (tp.flags&tcpFlagACK) != 0 {
				c.client = dst
				c.server = src
				c.roleResolved = true
			} else if len(tp.payload) > 0 {
				if looksLikeClientPayload(tp.payload) {
					c.client = src
					c.server = dst
					c.roleResolved = true
				} else if strings.HasPrefix(string(tp.payload), "HTTP/1.") {
					c.client = dst
					c.server = src
					c.roleResolved = true
				}
			}
		}

		// Track TCP handshake timestamps
		if (tp.flags&tcpFlagSYN) != 0 && (tp.flags&tcpFlagACK) == 0 && c.synTime.IsZero() {
			c.synTime = tp.ts
		} else if (tp.flags&tcpFlagSYN) != 0 && (tp.flags&tcpFlagACK) != 0 && c.synAckTime.IsZero() {
			c.synAckTime = tp.ts
		} else if (tp.flags&tcpFlagACK) != 0 && (tp.flags&tcpFlagSYN) == 0 && !c.synAckTime.IsZero() && c.ackTime.IsZero() {
			c.ackTime = tp.ts
		}

		if len(tp.payload) > 0 {
			if src == c.client {
				c.c2s.appendSegment(tp.ts, tp.seq, tp.payload)
			} else {
				c.s2c.appendSegment(tp.ts, tp.seq, tp.payload)
			}
		}
	}

	if len(connOrder) == 0 {
		return nil, fmt.Errorf("no TCP streams found in capture file")
	}

	var records []timedRecord
	seqOrder := 0
	addInfo := func(msg string, ts time.Duration) {
		if ts < 0 {
			ts = 0
		}
		seqOrder++
		records = append(records, timedRecord{
			isInfo: true,
			info:   msg,
			ts:     ts,
			order:  seqOrder,
		})
	}
	addEvent := func(ev event.FrameEvent) {
		if ev.Timestamp < 0 {
			ev.Timestamp = 0
		}
		seqOrder++
		records = append(records, timedRecord{
			isInfo: false,
			ts:     ev.Timestamp,
			order:  seqOrder,
			ev:     ev,
		})
	}

	for _, key := range connOrder {
		c := conns[key]
		cBytes := c.c2s.buf.Bytes()
		sBytes := c.s2c.buf.Bytes()

		if len(cBytes) == 0 && len(sBytes) == 0 && c.synTime.IsZero() {
			continue
		}

		isTLS := len(cBytes) >= 6 && cBytes[0] == 0x16 && cBytes[1] == 0x03
		isH2C := strings.HasPrefix(string(cBytes), http2.ClientPreface)

		if opts.ProtocolFilter != "" {
			if opts.ProtocolFilter == "h3" {
				continue
			}
			if opts.ProtocolFilter == "h2" && !isH2C && !isTLS {
				continue
			}
			if opts.ProtocolFilter == "h1" && isH2C {
				continue
			}
		}

		// Report TCP connection establishment if handshake was captured
		var tcpDoneTime time.Time
		var tcpDur time.Duration
		if !c.synTime.IsZero() {
			if !c.ackTime.IsZero() {
				tcpDoneTime = c.ackTime
				tcpDur = c.ackTime.Sub(c.synTime)
			} else if !c.synAckTime.IsZero() {
				tcpDoneTime = c.synAckTime
				tcpDur = c.synAckTime.Sub(c.synTime)
			}
		}
		if tcpDoneTime.IsZero() {
			tcpDoneTime = c.firstTime
		}

		tcpDurMs := float64(tcpDur.Microseconds()) / 1000.0
		if isTLS {
			addInfo(fmt.Sprintf("* TCP Connected to %s (%.1fms)", c.server.String(), tcpDurMs), tcpDoneTime.Sub(baseTime))
			parseTLSHandshakeInfo(c, baseTime, addInfo)
			continue
		}

		addInfo(fmt.Sprintf("* Connected to %s (TCP, %.1fms)", c.server.String(), tcpDurMs), tcpDoneTime.Sub(baseTime))

		if isH2C {
			parseH2CConnection(c, baseTime, opts, addEvent)
		} else {
			parseH1Connection(c, baseTime, opts, addInfo, addEvent)
		}
	}

	if opts.ProtocolFilter != "" {
		hasEvents := false
		for _, r := range records {
			if !r.isInfo {
				hasEvents = true
				break
			}
		}
		if !hasEvents {
			return nil, fmt.Errorf("no captured traffic matched protocol filter %q", opts.ProtocolFilter)
		}
	}

	rec := event.NewRecorder(opts)
	for _, item := range records {
		if item.isInfo {
			rec.RecordInfo(item.info, item.ts)
		} else {
			rec.RecordEvent(item.ev)
		}
	}

	return rec.Events(), nil
}

func parseTLSHandshakeInfo(c *tcpConnection, baseTime time.Time, addInfo func(string, time.Duration)) {
	cBytes := c.c2s.buf.Bytes()
	sBytes := c.s2c.buf.Bytes()

	clientHelloTime := c.c2s.timeAtOffset(0, c.firstTime)
	serverHelloTime := c.s2c.timeAtOffset(0, clientHelloTime)
	tlsDur := serverHelloTime.Sub(clientHelloTime)
	if tlsDur < 0 {
		tlsDur = 0
	}

	versionStr := "TLSv1.3"
	cipherStr := "unknown"
	alpnStr := ""

	// Inspect ServerHello if present
	if len(sBytes) >= 9 && sBytes[0] == 0x16 && sBytes[1] == 0x03 && sBytes[5] == 0x02 {
		ver, cipher, alpn, ok := parseServerHello(sBytes[5:])
		if ok {
			versionStr = tls.VersionName(ver)
			cipherStr = tls.CipherSuiteName(cipher)
			alpnStr = alpn
		}
	}
	if alpnStr == "" {
		// Fallback to first ALPN offered in ClientHello if ServerHello encrypted it (TLS 1.3 EncryptedExtensions)
		if len(cBytes) >= 9 && cBytes[0] == 0x16 && cBytes[5] == 0x01 {
			alpnStr = parseClientHelloFirstALPN(cBytes[5:])
		}
		if alpnStr == "" {
			alpnStr = "h2"
		}
	}

	relTime := serverHelloTime.Sub(baseTime)
	addInfo(fmt.Sprintf("* TLS Handshake: %s, Cipher: %s (%.1fms)", versionStr, cipherStr, float64(tlsDur.Microseconds())/1000.0), relTime)
	addInfo(fmt.Sprintf("* Connected to %s (%s, ALPN: %s)", c.server.String(), versionStr, alpnStr), relTime)
	addInfo("* Note: Encrypted TLS application data skipped (plaintext HTTP/1.1 and h2c are supported in PCAP mode)", relTime)
}

func parseServerHello(hs []byte) (version uint16, cipher uint16, alpn string, ok bool) {
	// hs[0] == 0x02 (ServerHello), hs[1:4] == length
	if len(hs) < 38 {
		return 0, 0, "", false
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+msgLen <= len(hs) {
		hs = hs[:4+msgLen]
	}
	legacyVer := binary.BigEndian.Uint16(hs[4:6])
	version = legacyVer
	// Skip 32-byte random (hs[6:38])
	pos := 38
	if pos >= len(hs) {
		return version, 0, "", false
	}
	sessIDLen := int(hs[pos])
	pos += 1 + sessIDLen
	if pos+3 > len(hs) {
		return version, 0, "", false
	}
	cipher = binary.BigEndian.Uint16(hs[pos : pos+2])
	pos += 3 // cipher (2) + compression method (1)

	if pos+2 <= len(hs) {
		extTotalLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
		pos += 2
		endExt := pos + extTotalLen
		if endExt > len(hs) {
			endExt = len(hs)
		}
		for pos+4 <= endExt {
			extType := binary.BigEndian.Uint16(hs[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(hs[pos+2 : pos+4]))
			pos += 4
			if pos+extLen > endExt {
				break
			}
			extData := hs[pos : pos+extLen]
			pos += extLen

			switch extType {
			case 0x002b: // supported_versions (TLS 1.3)
				if len(extData) >= 2 {
					version = binary.BigEndian.Uint16(extData[0:2])
				}
			case 0x0010: // ALPN
				if len(extData) >= 3 {
					protoLen := int(extData[2])
					if 3+protoLen <= len(extData) {
						alpn = string(extData[3 : 3+protoLen])
					}
				}
			}
		}
	}
	return version, cipher, alpn, true
}

func parseClientHelloFirstALPN(hs []byte) string {
	if len(hs) < 38 {
		return ""
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+msgLen <= len(hs) {
		hs = hs[:4+msgLen]
	}
	pos := 38
	if pos >= len(hs) {
		return ""
	}
	sessIDLen := int(hs[pos])
	pos += 1 + sessIDLen
	if pos+2 > len(hs) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos >= len(hs) {
		return ""
	}
	compMethodsLen := int(hs[pos])
	pos += 1 + compMethodsLen
	if pos+2 > len(hs) {
		return ""
	}
	extTotalLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2
	endExt := pos + extTotalLen
	if endExt > len(hs) {
		endExt = len(hs)
	}
	for pos+4 <= endExt {
		extType := binary.BigEndian.Uint16(hs[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(hs[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > endExt {
			break
		}
		extData := hs[pos : pos+extLen]
		pos += extLen
		if extType == 0x0010 && len(extData) >= 3 {
			protoLen := int(extData[2])
			if 3+protoLen <= len(extData) {
				return string(extData[3 : 3+protoLen])
			}
		}
	}
	return ""
}

type countingReader struct {
	r      io.Reader
	offset int
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.offset += n
	return n, err
}

var pcapH2StaticTable = map[string]struct {
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

func getPCAPHPACKIndexInfo(name, value string, dyn map[string]int, nextIdx *int) string {
	key := name + ":" + value
	if e, ok := pcapH2StaticTable[key]; ok && e.HasValue {
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
	if e, ok := pcapH2StaticTable[name]; ok {
		return fmt.Sprintf("Literal, Indexed (Name Index: %d)", e.Index)
	}
	return "Literal, Indexed"
}

func parseH2CConnection(c *tcpConnection, baseTime time.Time, opts event.Options, addEvent func(event.FrameEvent)) {
	var rawEvents []event.FrameEvent

	// 1. Parse Client -> Server stream
	cBytes := c.c2s.buf.Bytes()
	if strings.HasPrefix(string(cBytes), http2.ClientPreface) {
		prefaceTS := c.c2s.timeAtOffset(0, c.firstTime).Sub(baseTime)
		rawEvents = append(rawEvents, event.FrameEvent{
			Timestamp: prefaceTS,
			Direction: event.DirSend,
			StreamID:  0,
			FrameType: event.FrameMagic,
			Length:    len(http2.ClientPreface),
			Details:   []string{`"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`},
		})
		cEvents := readH2Frames(&c.c2s, len(http2.ClientPreface), event.DirSend, baseTime, opts)
		rawEvents = append(rawEvents, cEvents...)
	}

	// 2. Parse Server -> Client stream
	sEvents := readH2Frames(&c.s2c, 0, event.DirRecv, baseTime, opts)
	rawEvents = append(rawEvents, sEvents...)

	// Sort chronologically while preserving direction order on ties
	for i := 0; i < len(rawEvents); i++ {
		for j := i + 1; j < len(rawEvents); j++ {
			if rawEvents[j].Timestamp < rawEvents[i].Timestamp {
				rawEvents[i], rawEvents[j] = rawEvents[j], rawEvents[i]
			}
		}
	}

	// Compute PING RTT if PING and PING ACK are present
	var lastPingSent time.Duration
	hasPingSent := false
	for i := range rawEvents {
		if rawEvents[i].FrameType == event.FramePing {
			if rawEvents[i].Direction == event.DirSend && (rawEvents[i].Flags&0x1) == 0 {
				lastPingSent = rawEvents[i].Timestamp
				hasPingSent = true
			} else if rawEvents[i].Direction == event.DirRecv && (rawEvents[i].Flags&0x1) != 0 && hasPingSent {
				rtt := rawEvents[i].Timestamp - lastPingSent
				if rtt >= 0 {
					rawEvents[i].Details = append(rawEvents[i].Details, fmt.Sprintf("RTT: %.2fms", float64(rtt.Microseconds())/1000.0))
				}
				hasPingSent = false
			}
		}
		addEvent(rawEvents[i])
	}
}

func readH2Frames(stream *tcpStream, startOffset int, dir event.Direction, baseTime time.Time, opts event.Options) []event.FrameEvent {
	raw := stream.buf.Bytes()
	if startOffset >= len(raw) {
		return nil
	}
	cr := &countingReader{
		r:      bytes.NewReader(raw[startOffset:]),
		offset: startOffset,
	}
	framer := http2.NewFramer(io.Discard, cr)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	dynTable := make(map[string]int)
	dynIndex := 62
	connWindow := int64(65535)
	streamWindows := make(map[uint32]int64)
	var out []event.FrameEvent

	for {
		frameStartOffset := cr.offset
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}
		ts := stream.timeAtOffset(frameStartOffset, time.Time{}).Sub(baseTime)

		switch fr := f.(type) {
		case *http2.SettingsFrame:
			var flagNames []string
			var details []string
			if fr.IsAck() {
				flagNames = append(flagNames, "ACK")
			} else {
				_ = fr.ForeachSetting(func(s http2.Setting) error {
					valStr := fmt.Sprintf("%d", s.Val)
					if s.ID == http2.SettingInitialWindowSize && s.Val >= 1048576 {
						valStr = fmt.Sprintf("%d (%dMB)", s.Val, s.Val/1048576)
					}
					details = append(details, fmt.Sprintf("%s: %s", s.ID.String(), valStr))
					return nil
				})
			}
			out = append(out, event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
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
			}
			rawHeaderBytes := 0
			var hdrs []event.HeaderField
			for _, hf := range fr.Fields {
				rawHeaderBytes += len(hf.Name) + len(hf.Value) + 32
				hdrs = append(hdrs, event.HeaderField{
					Name:      hf.Name,
					Value:     hf.Value,
					IndexInfo: getPCAPHPACKIndexInfo(hf.Name, hf.Value, dynTable, &dynIndex),
				})
			}
			out = append(out, event.FrameEvent{
				Timestamp:      ts,
				Direction:      dir,
				StreamID:       fr.StreamID,
				FrameType:      event.FrameHeaders,
				Length:         int(fr.Length),
				Flags:          uint8(fr.Flags),
				FlagNames:      flagNames,
				Headers:        hdrs,
				RawHeaderSize:  rawHeaderBytes,
				CompHeaderSize: int(fr.Length),
			})

		case *http2.DataFrame:
			var flagNames []string
			if fr.StreamEnded() {
				flagNames = append(flagNames, "END_STREAM")
			}
			if _, ok := streamWindows[fr.StreamID]; !ok {
				streamWindows[fr.StreamID] = 65535
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
			out = append(out, event.FrameEvent{
				Timestamp:          ts,
				Direction:          dir,
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

		case *http2.WindowUpdateFrame:
			var details []string
			if fr.StreamID == 0 {
				cBefore := connWindow
				connWindow += int64(fr.Increment)
				details = append(details, fmt.Sprintf("increment=%d [Conn Window: %d -> %d]", fr.Increment, cBefore, connWindow))
			} else {
				if _, ok := streamWindows[fr.StreamID]; !ok {
					streamWindows[fr.StreamID] = 65535
				}
				sBefore := streamWindows[fr.StreamID]
				streamWindows[fr.StreamID] += int64(fr.Increment)
				details = append(details, fmt.Sprintf("increment=%d [Stream %d Window: %d -> %d]", fr.Increment, fr.StreamID, sBefore, streamWindows[fr.StreamID]))
			}
			out = append(out, event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
				StreamID:  fr.StreamID,
				FrameType: event.FrameWindowUpdate,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				Details:   details,
			})

		case *http2.PingFrame:
			var flagNames []string
			if fr.IsAck() {
				flagNames = append(flagNames, "ACK")
			}
			out = append(out, event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
				StreamID:  0,
				FrameType: event.FramePing,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				FlagNames: flagNames,
			})

		case *http2.RSTStreamFrame:
			out = append(out, event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
				StreamID:  fr.StreamID,
				FrameType: event.FrameRSTStream,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				Details:   []string{fmt.Sprintf("ErrorCode: %s (0x%x)", fr.ErrCode.String(), uint32(fr.ErrCode))},
			})

		case *http2.GoAwayFrame:
			out = append(out, event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
				StreamID:  fr.StreamID,
				FrameType: event.FrameGoAway,
				Length:    int(fr.Length),
				Flags:     uint8(fr.Flags),
				Details:   []string{fmt.Sprintf("LastStreamID: %d, ErrCode: %s", fr.LastStreamID, fr.ErrCode.String())},
			})
		}
	}
	return out
}

func parseH1Connection(
	c *tcpConnection,
	baseTime time.Time,
	opts event.Options,
	addInfo func(string, time.Duration),
	addEvent func(event.FrameEvent),
) {
	cRaw := c.c2s.buf.Bytes()
	sRaw := c.s2c.buf.Bytes()
	cCr := &countingReader{r: bytes.NewReader(cRaw)}
	sCr := &countingReader{r: bytes.NewReader(sRaw)}
	cReader := bufio.NewReader(cCr)
	sReader := bufio.NewReader(sCr)

	reqIdx := 0
	for {
		reqStartOffset := len(cRaw) - cReader.Buffered() - (len(cRaw) - cCr.offset)
		if reqStartOffset < 0 {
			reqStartOffset = 0
		}
		reqLine, err := cReader.ReadString('\n')
		if err != nil {
			break
		}
		reqLineTrimmed := strings.TrimRight(reqLine, "\r\n")
		if reqLineTrimmed == "" {
			continue
		}
		reqTS := c.c2s.timeAtOffset(reqStartOffset, c.firstTime).Sub(baseTime)

		if reqIdx > 0 {
			addInfo(fmt.Sprintf("* Reusing existing connection to %s (Request #%d)", c.server.String(), reqIdx+1), reqTS)
		}

		parts := strings.SplitN(reqLineTrimmed, " ", 3)
		method := "GET"
		if len(parts) > 0 {
			method = parts[0]
		}

		addEvent(event.FrameEvent{
			Timestamp: reqTS,
			Direction: event.DirSend,
			FrameType: event.FrameRequestLine,
			Details:   []string{reqLineTrimmed},
		})

		reqHeaders, reqHdrLen, reqChunked, reqContentLen, _, _ := readH1Headers(cReader)
		addEvent(event.FrameEvent{
			Timestamp:     reqTS,
			Direction:     event.DirSend,
			FrameType:     event.FrameHeaders,
			Length:        reqHdrLen,
			Headers:       reqHeaders,
			RawHeaderSize: reqHdrLen,
		})

		readH1Body(cReader, reqChunked, reqContentLen, event.DirSend, reqTS, opts, addEvent)

		// Read matching HTTP/1.x response from sReader
		respStartOffset := len(sRaw) - sReader.Buffered() - (len(sRaw) - sCr.offset)
		if respStartOffset < 0 {
			respStartOffset = 0
		}
		statusLine, err := sReader.ReadString('\n')
		if err != nil {
			break
		}
		statusTrimmed := strings.TrimRight(statusLine, "\r\n")
		respTS := c.s2c.timeAtOffset(respStartOffset, c.firstTime).Sub(baseTime)
		if respTS < reqTS {
			respTS = reqTS
		}

		addEvent(event.FrameEvent{
			Timestamp: respTS,
			Direction: event.DirRecv,
			FrameType: event.FrameStatusLine,
			Details:   []string{statusTrimmed},
		})

		respHeaders, respHdrLen, respChunked, respContentLen, keepAliveVal, connVal := readH1Headers(sReader)
		addEvent(event.FrameEvent{
			Timestamp:     respTS,
			Direction:     event.DirRecv,
			FrameType:     event.FrameHeaders,
			Length:        respHdrLen,
			Headers:       respHeaders,
			RawHeaderSize: respHdrLen,
		})

		if method != "HEAD" {
			readH1Body(sReader, respChunked, respContentLen, event.DirRecv, respTS, opts, addEvent)
		}

		if strings.EqualFold(connVal, "close") {
			addInfo("* Connection closed by server", respTS)
		} else {
			msg := "* Connection kept alive"
			if keepAliveVal != "" {
				msg += fmt.Sprintf(" (Keep-Alive: %s)", keepAliveVal)
			}
			addInfo(msg, respTS)
		}
		reqIdx++
	}
}

func readH1Headers(r *bufio.Reader) (headers []event.HeaderField, totalLen int, isChunked bool, contentLen int64, keepAliveVal, connVal string) {
	contentLen = -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		totalLen += len(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			headers = append(headers, event.HeaderField{Name: name, Value: val})
			lower := strings.ToLower(name)
			switch lower {
			case "transfer-encoding":
				if strings.Contains(strings.ToLower(val), "chunked") {
					isChunked = true
				}
			case "content-length":
				if cl, err := strconv.ParseInt(val, 10, 64); err == nil {
					contentLen = cl
				}
			case "keep-alive":
				keepAliveVal = val
			case "connection":
				connVal = val
			}
		}
	}
	return
}

func readH1Body(
	r *bufio.Reader,
	isChunked bool,
	contentLen int64,
	dir event.Direction,
	ts time.Duration,
	opts event.Options,
	addEvent func(event.FrameEvent),
) {
	if isChunked {
		chunkIndex := 1
		for {
			sizeLine, err := r.ReadString('\n')
			if err != nil {
				break
			}
			sizeTrimmed := strings.TrimSpace(sizeLine)
			if semi := strings.Index(sizeTrimmed, ";"); semi != -1 {
				sizeTrimmed = sizeTrimmed[:semi]
			}
			chunkSize, err := strconv.ParseInt(sizeTrimmed, 16, 64)
			if err != nil {
				break
			}
			if chunkSize == 0 {
				for {
					tLine, err := r.ReadString('\n')
					if err != nil || strings.TrimRight(tLine, "\r\n") == "" {
						break
					}
				}
				addEvent(event.FrameEvent{
					Timestamp: ts,
					Direction: dir,
					FrameType: event.FrameChunk,
					Length:    0,
					Details:   []string{fmt.Sprintf("size=0B, chunk #%d, [FIN]", chunkIndex)},
				})
				break
			}
			data := make([]byte, chunkSize)
			if _, err := io.ReadFull(r, data); err != nil {
				break
			}
			_, _ = r.ReadString('\n')
			var payload []byte
			if opts.ShowBody {
				payload = data
			}
			addEvent(event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
				FrameType: event.FrameChunk,
				Length:    int(chunkSize),
				Details:   []string{fmt.Sprintf("size=%dB, chunk #%d", chunkSize, chunkIndex)},
				Payload:   payload,
			})
			chunkIndex++
		}
	} else if contentLen > 0 {
		buf := make([]byte, contentLen)
		n, _ := io.ReadFull(r, buf)
		if n > 0 {
			var payload []byte
			if opts.ShowBody {
				payload = buf[:n]
			}
			addEvent(event.FrameEvent{
				Timestamp: ts,
				Direction: dir,
				FrameType: event.FrameData,
				Length:    n,
				Details:   []string{fmt.Sprintf("body bytes: %d", n)},
				Payload:   payload,
			})
		}
	}
}
