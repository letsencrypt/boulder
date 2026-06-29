// Package s3 stores tilestore objects in an S3-compatible object store. Boulder
// runs it only against MinIO, so it sticks to the GetObject and PutObject
// operations every S3 implementation supports and avoids features MinIO does
// not honor, such as server-side checksums and conditional writes.
package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/letsencrypt/boulder/trees/tilestore"
)

// client is the subset of *s3.Client the Backend needs. Narrowing it lets tests
// substitute a fake.
type client interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Backend is a tilestore.Backend that stores each object under its key in one
// bucket. The caller supplies an already-configured client, so the endpoint,
// region, credentials, and the path-style addressing MinIO requires are set up
// outside this package.
type Backend struct {
	client client
	bucket string
}

// New returns a Backend that reads and writes objects in bucket through c.
func New(c client, bucket string) *Backend {
	return &Backend{client: c, bucket: bucket}
}

// Get reads the object for key, returning tilestore.ErrNotExist when the bucket
// holds no such object.
func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		respErr, ok := errors.AsType[*smithyhttp.ResponseError](err)
		if ok && respErr.HTTPStatusCode() == 404 {
			return nil, tilestore.ErrNotExist
		}
		return nil, fmt.Errorf("getting object %q: %w", key, err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("reading object %q: %w", key, err)
	}
	return data, nil
}

// Put writes data to the object for key, overwriting any existing object. It is
// a plain PutObject with no checksum or conditional-write options, which every
// S3 implementation including MinIO supports.
func (b *Backend) Put(ctx context.Context, key string, data []byte) error {
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("putting object %q: %w", key, err)
	}
	return nil
}

var _ tilestore.Backend = (*Backend)(nil)
