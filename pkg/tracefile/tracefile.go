package tracefile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/haccht/httpviz/pkg/event"
	"github.com/haccht/httpviz/pkg/har"
	"github.com/haccht/httpviz/pkg/pcap"
)

const (
	pcapMagicMicroBE = 0xa1b2c3d4
	pcapMagicMicroLE = 0xd4c3b2a1
	pcapMagicNanoBE  = 0xa1b23c4d
	pcapMagicNanoLE  = 0x4d3cb2a1
	pcapngMagicSHB   = 0x0a0d0d0a
)

// Format identifies the capture file type.
type Format string

const (
	FormatUnknown Format = ""
	FormatHAR     Format = "har"
	FormatPCAP    Format = "pcap"
)

// DetectFormat inspects the leading bytes and file extension to determine the capture format.
func DetectFormat(filename string, data []byte) Format {
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[0:4])
		switch magic {
		case pcapMagicMicroBE, pcapMagicMicroLE, pcapMagicNanoBE, pcapMagicNanoLE, pcapngMagicSHB:
			return FormatPCAP
		}
	}

	// Skip optional UTF-8 BOM and leading whitespace to check for JSON object start '{'
	trimmed := bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	trimmed = bytes.TrimLeft(trimmed, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return FormatHAR
	}

	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".har":
		return FormatHAR
	case ".pcap", ".pcapng", ".cap":
		return FormatPCAP
	}

	return FormatUnknown
}

// RunFile reads the file at path, auto-detects HAR or PCAP/PCAPNG format, and returns the parsed FrameEvents.
func RunFile(path string, opts event.Options) ([]event.FrameEvent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("capture file %q is empty", path)
	}

	format := DetectFormat(path, data)
	switch format {
	case FormatHAR:
		return har.Run(bytes.NewReader(data), opts)
	case FormatPCAP:
		return pcap.Run(bytes.NewReader(data), opts)
	default:
		return nil, fmt.Errorf("unsupported capture file format for %q (expected .har, .pcap, or .pcapng)", path)
	}
}
