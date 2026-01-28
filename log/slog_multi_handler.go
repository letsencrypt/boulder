// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code is copied directly from
// https://cs.opensource.google/go/go/+/refs/tags/go1.26rc2:src/log/slog/multi_handler.go;l=13
// The only modificiations are:
//
// * use the `slog.` package qualifier for slog types; and
// * unexport the multiHandler type and its constructor.
//
// It should be replaced with the stdlib MultiHandler when Boulder updates to
// go1.26.

package log

import (
	"context"
	"errors"
	"log/slog"
)

// newMultiHandler creates a [multiHandler] with the given Handlers.
func newMultiHandler(handlers ...slog.Handler) *multiHandler {
	h := make([]slog.Handler, len(handlers))
	copy(h, handlers)
	return &multiHandler{multi: h}
}

// multiHandler is a [Handler] that invokes all the given Handlers.
// Its Enable method reports whether any of the handlers' Enabled methods return true.
// Its Handle, WithAttr and WithGroup methods call the corresponding method on each of the enabled handlers.
type multiHandler struct {
	multi []slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for i := range h.multi {
		if h.multi[i].Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for i := range h.multi {
		if h.multi[i].Enabled(ctx, r.Level) {
			if err := h.multi[i].Handle(ctx, r.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h.multi))
	for i := range h.multi {
		handlers = append(handlers, h.multi[i].WithAttrs(attrs))
	}
	return &multiHandler{multi: handlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h.multi))
	for i := range h.multi {
		handlers = append(handlers, h.multi[i].WithGroup(name))
	}
	return &multiHandler{multi: handlers}
}
