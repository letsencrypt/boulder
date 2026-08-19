// Package bs3test provides an in-memory fake of the S3 client subset
// provided by the bs3 package, for use in tests.
package bs3test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
}

// FakeS3 implements the PutObject/GetObject/Bucket subset of the S3 API
// with an in-memory map.
//
// PutObject fails for an existing key only when IfNoneMatch is set.
type FakeS3 struct {
	mu sync.Mutex

	Objects map[string]StoredObject
}

func New() *FakeS3 {
	return &FakeS3{Objects: make(map[string]StoredObject)}
}

func (f *FakeS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.Objects[*params.Key]
	if ok && params.IfNoneMatch != nil {
		return nil, &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusPreconditionFailed}},
				Err:      errors.New("PreconditionFailed"),
			},
		}
	}
	body, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	f.Objects[*params.Key] = StoredObject{Data: body, ContentEncoding: params.ContentEncoding}
	return nil, nil
}

func (f *FakeS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.Objects[*params.Key]
	if ok {
		return &s3.GetObjectOutput{
			Body:            io.NopCloser(bytes.NewReader(o.Data)),
			ContentEncoding: o.ContentEncoding,
		}, nil
	}
	return nil, fmt.Errorf("not found")
}

func (f *FakeS3) Bucket() string {
	return "fakebucket"
}
