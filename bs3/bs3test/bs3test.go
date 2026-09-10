// Package bs3test provides an in-memory fake of the S3 client subset provided
// by the bs3 package, for use in tests.
package bs3test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// StoredObject is an object held by a FakeS3.
type StoredObject struct {
	Data            []byte
	ContentEncoding *string
	// ETag is set by PutObject. An object placed in Objects directly without
	// one has no ETag, so GetObject returns none and IfMatch never matches it.
	ETag string
}

// FakeS3 implements the PutObject/GetObject/Bucket subset of the S3 API with an
// in-memory map.
type FakeS3 struct {
	mu sync.Mutex

	Objects map[string]StoredObject
}

func New() *FakeS3 {
	return &FakeS3{Objects: make(map[string]StoredObject)}
}

func responseError(status int) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      errors.New(http.StatusText(status)),
		},
	}
}

// PutObject stores params.Body under params.Key. It fails with 412 Precondition
// Failed when params.IfNoneMatch is set and the key exists, or when
// params.IfMatch is set and does not match the stored ETag, and with 404 Not
// Found when params.IfMatch is set and the key does not exist.
func (f *FakeS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.Objects[*params.Key]
	if ok && params.IfNoneMatch != nil {
		return nil, responseError(http.StatusPreconditionFailed)
	}
	if params.IfMatch != nil && !ok {
		return nil, responseError(http.StatusNotFound)
	}
	if params.IfMatch != nil && existing.ETag != *params.IfMatch {
		return nil, responseError(http.StatusPreconditionFailed)
	}

	body, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(body)
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""
	f.Objects[*params.Key] = StoredObject{Data: body, ContentEncoding: params.ContentEncoding, ETag: etag}
	return &s3.PutObjectOutput{ETag: &etag}, nil
}

// GetObject returns the object stored under params.Key, failing with 404 Not
// Found when there is none.
func (f *FakeS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.Objects[*params.Key]
	if !ok {
		return nil, responseError(http.StatusNotFound)
	}
	var etag *string
	if o.ETag != "" {
		etag = &o.ETag
	}
	return &s3.GetObjectOutput{
		Body:            io.NopCloser(bytes.NewReader(o.Data)),
		ContentEncoding: o.ContentEncoding,
		ETag:            etag,
	}, nil
}

// Bucket returns a fixed bucket name, "fakebucket".
func (f *FakeS3) Bucket() string {
	return "fakebucket"
}
