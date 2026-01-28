package log

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
)

// checksumWriter implements the io.Writer interface. It computes the CRC32
// checksum of all lines written to it, prepends that value to the original
// line, and passes the result through to an inner io.Writer.
//
// The slog package [guarantees](https://pkg.go.dev/log/slog#JSONHandler.Handle)
// that "each call to Handle results in a single serialized call to
// io.Writer.Write".
type checksumWriter struct {
	inner io.Writer
}

// NewChecksumWriter returns a checksumWriter which wraps the given io.Writer.
func NewChecksumWriter(inner io.Writer) *checksumWriter {
	return &checksumWriter{inner: inner}
}

// Write implements the io.Writer interface. Each call to Write results in
// exactly one call to the wrapped io.Writer's .Write method.
func (w *checksumWriter) Write(in []byte) (int, error) {
	out := bytes.Buffer{}
	out.WriteString(LogLineChecksum(string(in)))
	out.WriteString(" ")
	out.Write(in)
	size, err := out.WriteTo(w.inner)
	return int(size), err
}

var _ io.Writer = (*checksumWriter)(nil)

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
