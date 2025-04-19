package e2e

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/lstoll/tinkrotate/s3store"
)

func TestAutoRotator_S3_BlackBox(t *testing.T) {
	var (
		minioAddr      = os.Getenv("MINIO_ADDR")
		minioAccessKey = os.Getenv("MINIO_ACCESS_KEY")
		minioSecretKey = os.Getenv("MINIO_SECRET_KEY")
	)
	if minioAddr == "" || minioAccessKey == "" || minioSecretKey == "" {
		t.Skip("Skipping S3 test because MINIO_ADDR, MINIO_ACCESS_KEY, or MINIO_SECRET_KEY is not set")
	}

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(minioAccessKey, minioSecretKey, ""),
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &minioAddr
		o.Region = "us-east-1"
		o.UsePathStyle = true
	})

	bucketName := "test-bucket-" + uuid.New().String()
	_, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	t.Cleanup(func() {
		// Delete all objects in bucket
		listOutput, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Errorf("failed to list objects in bucket: %v", err)
			return
		}

		for _, obj := range listOutput.Contents {
			_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			})
			if err != nil {
				t.Errorf("failed to delete object %s: %v", *obj.Key, err)
			}
		}

		// Delete bucket
		_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Errorf("failed to delete test bucket: %v", err)
		}
	})

	store, err := s3store.NewS3Store(client, bucketName, "test-key")
	if err != nil {
		t.Fatalf("failed to create S3 store: %v", err)
	}
	runStoreTest(t, store)
}
