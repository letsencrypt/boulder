package blog

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
)

// newChecksumWriter returns a checksumWriter which wraps the given io.Writer.
func newChecksumWriter(inner io.Writer) *checksumWriter {
	return &checksumWriter{inner: inner}
}

// checksumWriter implements the io.Writer interface. It computes the CRC32
// checksum of each line written to it before passing the result through to a
// wrapped io.Writer. It is intended for use as the io.Writer passed to a slog
// Handler.
type checksumWriter struct {
	inner io.Writer
}

var _ io.Writer = (*checksumWriter)(nil)

// Write implements the io.Writer interface. It computes the CRC32 checksum of
// its input, concatenates the checksum and the original input separated by a
// space, and forwards the result to the inner io.Writer.
//
// The slog package guarantees that "each call to Handle results in a single
// serialized call to io.Writer.Write". Similarly, each call to this method also
// results in a single call to the wrapped io.Writer.Write. This means that we
// are computing writing exactly one checksum per call to slog.Logger.Handle.
func (w *checksumWriter) Write(in []byte) (int, error) {
	out := bytes.Buffer{}
	out.WriteString(LogLineChecksum(string(in)))
	out.WriteString(" ")
	out.Write(in)
	size, err := out.WriteTo(w.inner)
	return int(size), err
}

// LogLineChecksum computes a CRC32 over the log line, which can be checked to
// ensure no unexpected log corruption has occurred. This function is exported
// for use by the log-validator.
func LogLineChecksum(line string) string {
	crc := crc32.ChecksumIEEE([]byte(line))
	buf := make([]byte, crc32.Size)
	// Error is unreachable because we provide a supported type and buffer size
	_, _ = binary.Encode(buf, binary.LittleEndian, crc)
	return base64.RawURLEncoding.EncodeToString(buf)
}
