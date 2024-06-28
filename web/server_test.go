package web

import (
	"context"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

func TestNewServer(t *testing.T) {
	srv := NewServer(":0", nil, blog.NewMock())

	go func() {
		err := srv.ListenAndServe()
		test.AssertNotError(t, err, "Could not create server")
	}()

	err := srv.Shutdown(context.TODO())
	test.AssertNotError(t, err, "Could not shut down server")
}
