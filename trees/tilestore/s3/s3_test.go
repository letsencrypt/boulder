package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/letsencrypt/boulder/trees/tilestore"
)

// fakeS3 is an in-memory client keyed by "bucket/key". A missing object returns
// the same 404 ResponseError a real S3 GetObject does.
type fakeS3 struct {
	objects map[string][]byte
	putErr  error
}

func (f *fakeS3) PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*in.Bucket+"/"+*in.Key] = data
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	data, ok := f.objects[*in.Bucket+"/"+*in.Key]
	if !ok {
		return nil, &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 404}}}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func TestRoundTripAndOverwrite(t *testing.T) {
	b := New(&fakeS3{objects: map[string][]byte{}}, "bucket")
	const key = "example.com%2Flog/tile/0/000"

	_, err := b.Get(t.Context(), key)
	if !errors.Is(err, tilestore.ErrNotExist) {
		t.Fatalf("Get of a missing key = %v, want ErrNotExist", err)
	}

	err = b.Put(t.Context(), key, []byte("first"))
	if err != nil {
		t.Fatalf("Put: %s", err)
	}
	got, err := b.Get(t.Context(), key)
	if err != nil || string(got) != "first" {
		t.Fatalf("Get = (%q, %v), want (\"first\", nil)", got, err)
	}

	err = b.Put(t.Context(), key, []byte("second"))
	if err != nil {
		t.Fatalf("Put overwrite: %s", err)
	}
	got, err = b.Get(t.Context(), key)
	if err != nil || string(got) != "second" {
		t.Fatalf("Get after overwrite = (%q, %v), want (\"second\", nil)", got, err)
	}
}

// TestGetWrapsNon404 confirms a non-404 GetObject error is returned rather than
// masquerading as ErrNotExist.
func TestGetWrapsNon404(t *testing.T) {
	b := New(brokenGet{}, "bucket")
	_, err := b.Get(t.Context(), "k")
	if err == nil || errors.Is(err, tilestore.ErrNotExist) {
		t.Fatalf("Get on a broken client = %v, want a non-ErrNotExist error", err)
	}
}

func TestPutReturnsError(t *testing.T) {
	b := New(&fakeS3{objects: map[string][]byte{}, putErr: errors.New("boom")}, "bucket")
	err := b.Put(t.Context(), "k", []byte("v"))
	if err == nil {
		t.Fatal("Put with a failing client = nil error, want error")
	}
}

// brokenGet returns a 500-class ResponseError from GetObject.
type brokenGet struct{}

func (brokenGet) PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (brokenGet) GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 500}}}
}
