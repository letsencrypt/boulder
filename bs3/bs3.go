// Package bs3 contains utilities for interacting with S3-compatible object storage.
package bs3

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsl "github.com/aws/smithy-go/logging"
	blog "github.com/letsencrypt/boulder/log"
)

type Config struct {
	// S3Endpoint is the URL at which the S3-API-compatible object storage
	// service can be reached. This can be used to point to a non-Amazon storage
	// service, or to point to a fake service for testing. It should be left
	// blank by default.
	S3Endpoint string
	// S3Bucket is the AWS S3Bucket that uploads should go to. Must be created
	// (and have appropriate permissions set) beforehand.
	S3Bucket string
	// AWSConfigFile is the path to a file on disk containing an AWS config.
	// The format of the configuration file is specified at
	// https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html.
	AWSConfigFile string
	// AWSCredsFile is the path to a file on disk containing AWS credentials.
	// The format of the credentials file is specified at
	// https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html.
	AWSCredsFile string
}

// awsLogger implements the github.com/aws/smithy-go/logging.Logger interface.
type awsLogger struct {
	blog.Logger
}

func (log awsLogger) Logf(c awsl.Classification, format string, v ...any) {
	switch c {
	case awsl.Debug:
		log.Debugf(format, v...)
	case awsl.Warn:
		log.Warningf(format, v...)
	}
}

func FromConfig(c Config, logger blog.Logger) (*Client, error) {
	// Load the "default" AWS configuration, but override the set of config and
	// credential files it reads from to just those specified in our JSON config,
	// to ensure that it's not accidentally reading anything from the homedir or
	// its other default config locations.
	awsConfig, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithSharedConfigFiles([]string{c.AWSConfigFile}),
		config.WithSharedCredentialsFiles([]string{c.AWSCredsFile}),
		config.WithHTTPClient(new(http.Client)),
		config.WithLogger(awsLogger{logger}),
		config.WithClientLogMode(aws.LogRequestEventMessage|aws.LogResponseEventMessage),
	)
	if err != nil {
		return nil, err
	}

	s3opts := make([]func(*s3.Options), 0)
	if c.S3Endpoint != "" {
		s3opts = append(
			s3opts,
			s3.WithEndpointResolver(s3.EndpointResolverFromURL(c.S3Endpoint)),
			func(o *s3.Options) { o.UsePathStyle = true },
		)
	}
	return &Client{s3.NewFromConfig(awsConfig, s3opts...), c.S3Bucket}, nil
}

type Client struct {
	*s3.Client
	// bucket is carried along from the config for convenience in constructing PutObjectInput and GetObjectInput.
	bucket string
}

func (c *Client) Bucket() string {
	return c.bucket
}
