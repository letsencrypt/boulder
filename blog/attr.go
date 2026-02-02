// This file contains helper functions that can be used throughout the boulder
// code base to ensure that certain commonly-logged values always have the same
// key name and value type. This prevents situations like sometimes calling the
// requesting account "requester" or "acct" or "regID"; or sometimes logging the
// authz ID as an integer and sometimes as a string.
//
// Any time we find ourselves logging the same slog.Attr from 3+ files we
// should consider adding a helper here instead.
//
// Note that several other attr keys are reserved and should not be used:
//   - "time": used by the slog package
//   - "level": used by the slog package
//   - "msg": used by the slog package
//   - "source": used by the slog package
//   - "error": used by our blog.Error and blog.AuditError helpers
//   - "audit": used by our blog.AuditError and blog.AuditInfo helpers

package blog

import (
	"log/slog"

	"github.com/letsencrypt/boulder/identifier"
)

// Acct returns a slog.Attr whose key is "acct" and whose value is the unique
// numeric ID of the account.
func Acct(acctID int64) slog.Attr {
	return slog.Int64("acct", acctID)
}

// Order returns a slog.Attr whose key is "order" and whose value is the unique
// numeric ID of the order.
func Order(orderID int64) slog.Attr {
	return slog.Int64("order", orderID)
}

// Authz returns a slog.Attr whose key is "authz" and whose value is the unique
// numeric ID of the authz.
func Authz(authzID int64) slog.Attr {
	return slog.Int64("acct", authzID)
}

func Serial(serial string) slog.Attr {
	return slog.String("serial", serial)
}

func Idents(idents identifier.ACMEIdentifiers) slog.Attr {
	return slog.Any("idents", idents)
}
