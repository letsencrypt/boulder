package g2s

import (
	"fmt"
)

type sendable interface {
	Message() string
}

type sampling struct {
	enabled bool
	rate    float32
}

func (s *sampling) Suffix() string {
	if s.enabled {
		return fmt.Sprintf("|@%f", s.rate)
	}
	return ""
}

type counterUpdate struct {
	bucket string
	n      int
	sampling
}

func (u *counterUpdate) Message() string {
	return fmt.Sprintf("%s:%d|c%s\n", u.bucket, u.n, u.sampling.Suffix())
}

type timingUpdate struct {
	bucket string
	ms     int
	sampling
}

func (u *timingUpdate) Message() string {
	return fmt.Sprintf("%s:%d|ms\n", u.bucket, u.ms)
}

type gaugeUpdate struct {
	bucket string
	val    string
	sampling
}

func (u *gaugeUpdate) Message() string {
	return fmt.Sprintf("%s:%s|g\n", u.bucket, u.val)
}
