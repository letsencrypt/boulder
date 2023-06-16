package ratelimits

import "time"

type source interface {
	Set(prefix Prefix, id string, tat time.Time)
	Get(prefix Prefix, id string) (time.Time, error)
}
