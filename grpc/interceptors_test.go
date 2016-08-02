package grpc

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

var fc = clock.NewFake()

func testHandler(_ context.Context, i interface{}) (interface{}, error) {
	if i != nil {
		return nil, errors.New("")
	}
	fc.Sleep(time.Second)
	return nil, nil
}

func TestServerInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := metrics.NewMockStatter(ctrl)
	stats := metrics.NewStatsdScope(statter, "fake")
	si := serverInterceptor{stats, fc}

	statter.EXPECT().Inc("fake.gRPC.NoInfo", int64(1), float32(1.0)).Return(nil)
	_, err := si.intercept(context.Background(), nil, nil, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail with a nil grpc.UnaryServerInfo")

	statter.EXPECT().Inc("fake.gRPC.test", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPC.test.InProgress", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().TimingDuration("fake.gRPC.test", time.Second, float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPC.test.InProgress", int64(-1), float32(1.0)).Return(nil)
	_, err = si.intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "test"}, testHandler)
	test.AssertNotError(t, err, "si.intercept failed with a non-nil grpc.UnaryServerInfo")

	statter.EXPECT().Inc("fake.gRPC.broke-test", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPC.broke-test.InProgress", int64(1), float32(1.0)).Return(nil)
	statter.EXPECT().TimingDuration("fake.gRPC.broke-test", time.Duration(0), float32(1.0)).Return(nil)
	statter.EXPECT().GaugeDelta("fake.gRPC.broke-test.InProgress", int64(-1), float32(1.0)).Return(nil)
	statter.EXPECT().Inc("fake.gRPC.broke-test.Failed", int64(1), float32(1.0)).Return(nil)
	_, err = si.intercept(context.Background(), 0, &grpc.UnaryServerInfo{FullMethod: "broke-test"}, testHandler)
	test.AssertError(t, err, "si.intercept didn't fail when handler returned a error")
}
