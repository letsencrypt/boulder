// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"time"
	"unicode"
)

const (
	tagUTCTime         = 23
	tagGeneralizedTime = 24
)

func isDigit(b byte) bool {
	return unicode.IsDigit(rune(b))
}

func bytesToInt(bytes []byte) (int, error) {
	return strconv.Atoi(string(bytes))
}

func parseUTCTime(bytes []byte) (time.Time, error) {
	var err error
	var year, month, day int
	var hour, min, sec int
	var tz *time.Location

	// YYMMDDhhmm
	if len(bytes) < 10 {
		return time.Time{}, errors.New("UTCTime is too short")
	}
	year, err = bytesToInt(bytes[0:2])
	if err != nil {
		return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
	}

	month, err = bytesToInt(bytes[2:4])
	if err != nil {
		return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
	}

	day, err = bytesToInt(bytes[4:6])
	if err != nil {
		return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
	}

	hour, err = bytesToInt(bytes[6:8])
	if err != nil {
		return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
	}

	min, err = bytesToInt(bytes[8:10])
	if err != nil {
		return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
	}

	bytes = bytes[10:]

	// (optional) ss
	if len(bytes) >= 2 && isDigit(bytes[0]) {
		sec, err = bytesToInt(bytes[0:2])
		if err != nil {
			return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
		}
		bytes = bytes[2:]
	}

	// timezone (required but allow it to be omitted, since this is a common error)
	if len(bytes) >= 1 {
		if bytes[0] == 'Z' {
			tz = time.UTC
			bytes = bytes[1:]
		} else if bytes[0] == '+' {
			// +hhmm
			if len(bytes) < 5 {
				return time.Time{}, errors.New("UTCTime positive timezone offset is too short")
			}
			tzHour, err := bytesToInt(bytes[1:3])
			if err != nil {
				return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
			}

			tzMin, err := bytesToInt(bytes[3:5])
			if err != nil {
				return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
			}

			tz = time.FixedZone("", tzHour*3600+tzMin*60)
			bytes = bytes[5:]
		} else if bytes[0] == '-' {
			// -hhmm
			if len(bytes) < 5 {
				return time.Time{}, errors.New("UTCTime negative timezone offset is too short")
			}
			tzHour, err := bytesToInt(bytes[1:3])
			if err != nil {
				return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
			}

			tzMin, err := bytesToInt(bytes[3:5])
			if err != nil {
				return time.Time{}, errors.New("UTCTime contains invalid integer: " + err.Error())
			}

			tz = time.FixedZone("", -1*(tzHour*3600+tzMin*60))
			bytes = bytes[5:]
		}
	} else {
		tz = time.UTC
	}

	if len(bytes) > 0 {
		return time.Time{}, errors.New("UTCTime has trailing garbage")
	}

	// https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
	if year >= 50 {
		year = 1900 + year
	} else {
		year = 2000 + year
	}

	return time.Date(year, time.Month(month), day, hour, min, sec, 0, tz), nil
}

func parseGeneralizedTime(bytes []byte) (time.Time, error) {
	var err error
	var year, month, day int
	var hour, min, sec, ms int
	var tz *time.Location

	// YYYYMMDDHH
	if len(bytes) < 10 {
		return time.Time{}, errors.New("GeneralizedTime is too short")
	}
	year, err = bytesToInt(bytes[0:4])
	if err != nil {
		return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
	}

	month, err = bytesToInt(bytes[4:6])
	if err != nil {
		return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
	}

	day, err = bytesToInt(bytes[6:8])
	if err != nil {
		return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
	}

	hour, err = bytesToInt(bytes[8:10])
	if err != nil {
		return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
	}

	bytes = bytes[10:]

	// (optional) MM
	if len(bytes) >= 2 && isDigit(bytes[0]) {
		min, err = bytesToInt(bytes[0:2])
		if err != nil {
			return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
		}
		bytes = bytes[2:]
		// (optional) SS
		if len(bytes) >= 2 && isDigit(bytes[0]) {
			sec, err = bytesToInt(bytes[0:2])
			if err != nil {
				return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
			}
			bytes = bytes[2:]
			// (optional) .fff
			if len(bytes) >= 1 && bytes[0] == '.' {
				if len(bytes) < 4 {
					return time.Time{}, errors.New("GeneralizedTime fractional seconds is too short")
				}
				ms, err = bytesToInt(bytes[1:4])
				if err != nil {
					return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
				}
				bytes = bytes[4:]
			}
		}
	}

	// timezone (Z or +hhmm or -hhmm or nothing)
	if len(bytes) >= 1 {
		if bytes[0] == 'Z' {
			bytes = bytes[1:]
			tz = time.UTC
		} else if bytes[0] == '+' {
			// +hhmm
			if len(bytes) < 5 {
				return time.Time{}, errors.New("GeneralizedTime positive timezone offset is too short")
			}
			tzHour, err := bytesToInt(bytes[1:3])
			if err != nil {
				return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
			}

			tzMin, err := bytesToInt(bytes[3:5])
			if err != nil {
				return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
			}

			tz = time.FixedZone("", tzHour*3600+tzMin*60)
			bytes = bytes[5:]
		} else if bytes[0] == '-' {
			// -hhmm
			if len(bytes) < 5 {
				return time.Time{}, errors.New("GeneralizedTime negative timezone offset is too short")
			}
			tzHour, err := bytesToInt(bytes[1:3])
			if err != nil {
				return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
			}

			tzMin, err := bytesToInt(bytes[3:5])
			if err != nil {
				return time.Time{}, errors.New("GeneralizedTime contains invalid integer: " + err.Error())
			}

			tz = time.FixedZone("", -1*(tzHour*3600+tzMin*60))
			bytes = bytes[5:]
		}
	} else {
		tz = time.UTC
	}

	if len(bytes) > 0 {
		return time.Time{}, errors.New("GeneralizedTime has trailing garbage")
	}

	return time.Date(year, time.Month(month), day, hour, min, sec, ms*1000*1000, tz), nil
}

func decodeASN1Time(value *asn1.RawValue) (time.Time, error) {
	if !value.IsCompound && value.Class == 0 {
		if value.Tag == tagUTCTime {
			return parseUTCTime(value.Bytes)
		} else if value.Tag == tagGeneralizedTime {
			return parseGeneralizedTime(value.Bytes)
		}
	}
	return time.Time{}, errors.New("Not a time value")
}
