package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	endpoint = "http://boulder-minio:9000"
	bucket   = "boulder-mtc-tiles"
)

func main() {
	ctx := context.Background()
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", ""),
		UsePathStyle: true,
	})

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			fmt.Printf("while listing objects to delete: %s\n", err)
			os.Exit(1)
		}
		if len(page.Contents) == 0 {
			continue
		}

		ids := make([]types.ObjectIdentifier, len(page.Contents))
		for i, obj := range page.Contents {
			ids[i] = types.ObjectIdentifier{Key: obj.Key}
		}
		_, err = client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{Objects: ids},
		})
		if err != nil {
			fmt.Printf("while deleting objects: %s\n", err)
			os.Exit(1)
		}
	}
}
