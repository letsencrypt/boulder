package log

import "log/slog"

func AcctAttr(acctID int) slog.Attr {
	return slog.Int("acct", acctID)
}

func OrderAttr(orderID int) slog.Attr {
	return slog.Int("order", orderID)
}

func AuthzAttr(authzID int) slog.Attr {
	return slog.Int("acct", authzID)
}
