package s3store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	awshttp "github.com/aws/smithy-go/transport/http"
	"google.golang.org/protobuf/proto"
	"lds.li/tinkrotate"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var _ tinkrotate.ManagedStore = (*S3Store)(nil)

type s3StoredData struct {
	KeysetData   []byte `json:"keyset_data"`
	MetadataData []byte `json:"metadata_data"`
}

type S3Store struct {
	s3Client *s3.Client
	bucket   string
	prefix   string
	kek      tink.AEAD
}

type S3StoreOption func(*S3Store)

func WithS3KEK(kek tink.AEAD) S3StoreOption {
	return func(s *S3Store) {
		s.kek = kek
	}
}

func WithS3Prefix(prefix string) S3StoreOption {
	return func(s *S3Store) {
		s.prefix = prefix
	}
}

func NewS3Store(s3Client *s3.Client, bucket string, opts ...S3StoreOption) (*S3Store, error) {
	if s3Client == nil {
		return nil, errors.New("s3 client cannot be nil")
	}
	if bucket == "" {
		return nil, errors.New("s3 bucket name cannot be empty")
	}

	s := &S3Store{
		s3Client: s3Client,
		bucket:   bucket,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

func (s *S3Store) ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*tinkrotate.ReadResult, error) {
	slog.Debug("S3Store: ReadKeysetAndMetadata called", "bucket", s.bucket, "objectKey", s.objectKey(keysetName))
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(keysetName)),
	}

	getObjectOutput, err := s.s3Client.GetObject(ctx, getInput)
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return &tinkrotate.ReadResult{Context: ""}, tinkrotate.ErrKeysetNotFound
		}
		return nil, fmt.Errorf("failed to get object %s/%s from S3: %w", s.bucket, s.objectKey(keysetName), err)
	}
	defer getObjectOutput.Body.Close()

	objectBytes, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object body from S3: %w", err)
	}

	var stored s3StoredData
	err = json.Unmarshal(objectBytes, &stored)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored data JSON: %w", err)
	}

	var handle *keyset.Handle
	reader := keyset.NewBinaryReader(bytes.NewReader(stored.KeysetData))
	if s.kek != nil {
		handle, err = keyset.ReadWithAssociatedData(reader, s.kek, []byte(keysetName))
		if err != nil {
			return nil, fmt.Errorf("failed to read keyset handle: %w", err)
		}
	} else {
		handle, err = insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read keyset handle: %w", err)
		}
	}

	metadata := &tinkrotatev1.KeyRotationMetadata{}
	err = proto.Unmarshal(stored.MetadataData, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata protobuf: %w", err)
	}

	currentETag := ""
	if getObjectOutput.ETag != nil {
		currentETag = *getObjectOutput.ETag
	}
	if currentETag == "" {
		return nil, errors.New("S3 GetObject succeeded but returned an empty ETag")
	}

	return &tinkrotate.ReadResult{
		Handle:   handle,
		Metadata: metadata,
		Context:  currentETag,
	}, nil
}

func (s *S3Store) WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext any) error {
	slog.Debug("S3Store: WriteKeysetAndMetadata called", "bucket", s.bucket, "objectKey", s.objectKey(keysetName))
	if handle == nil || metadata == nil {
		return errors.New("handle and metadata cannot be nil for writing")
	}

	var expectedETag string
	isInsert := false
	if expectedContext == nil {
		expectedETag = ""
		isInsert = true
	} else {
		etag, ok := expectedContext.(string)
		if !ok {
			return fmt.Errorf("invalid expectedContext type: expected string (ETag), got %T", expectedContext)
		}
		expectedETag = etag
		if expectedETag == "" {
			isInsert = true
		}
	}

	metadataData, err := proto.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata protobuf: %w", err)
	}

	keysetBuf := new(bytes.Buffer)
	if s.kek != nil {
		writer := keyset.NewBinaryWriter(keysetBuf)
		err = handle.WriteWithAssociatedData(writer, s.kek, []byte(keysetName))
		if err != nil {
			return fmt.Errorf("failed to write keyset handle: %w", err)
		}
	} else {
		if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(keysetBuf)); err != nil {
			return fmt.Errorf("failed to write keyset handle: %w", err)
		}
	}

	stored := s3StoredData{
		KeysetData:   keysetBuf.Bytes(),
		MetadataData: metadataData,
	}

	bodyBytes, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal data for S3 object: %w", err)
	}

	putInput := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(keysetName)),
		Body:   bytes.NewReader(bodyBytes),
	}

	if isInsert {
		putInput.IfNoneMatch = aws.String("*")
	} else {
		if expectedETag == "" {
			return errors.New("invalid state: expected non-empty ETag for update operation")
		}
		putInput.IfMatch = aws.String(expectedETag)
	}

	_, err = s.s3Client.PutObject(ctx, putInput)
	if err != nil {
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) && responseError.HTTPStatusCode() == 412 {
			return tinkrotate.ErrOptimisticLockFailed
		}

		return fmt.Errorf("failed to put object %s to S3: %w", s.objectKey(keysetName), err)
	}

	return nil
}

func (s *S3Store) GetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	slog.Debug("S3Store: GetHandle called", "bucket", s.bucket, "objectKey", s.objectKey(keysetName))
	readResult, err := s.ReadKeysetAndMetadata(ctx, keysetName)
	if err != nil {
		if errors.Is(err, tinkrotate.ErrKeysetNotFound) {
			return nil, fmt.Errorf("keyset '%s': %w", s.objectKey(keysetName), tinkrotate.ErrKeysetNotFound)
		}
		return nil, fmt.Errorf("failed to read for GetHandle: %w", err)
	}
	if readResult.Handle == nil {
		return nil, fmt.Errorf("internal error: ReadKeysetAndMetadata succeeded but returned nil handle for %s", s.objectKey(keysetName))
	}
	return readResult.Handle, nil
}

func (s *S3Store) GetPublicHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	slog.Debug("S3Store: GetPublicHandle called", "bucket", s.bucket, "objectKey", s.objectKey(keysetName))
	fullHandle, err := s.GetHandle(ctx, keysetName)
	if err != nil {
		return nil, err
	}
	publicHandle, err := fullHandle.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public keyset handle for '%s': %w", s.objectKey(keysetName), err)
	}
	return publicHandle, nil
}

func (s *S3Store) ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error {
	slog.Debug("S3Store: ForEachKeyset called", "bucket", s.bucket, "prefix", s.prefix)

	var continuationToken *string

	for {
		listInput := &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.bucket),
			ContinuationToken: continuationToken,
		}

		if s.prefix != "" {
			listInput.Prefix = aws.String(s.prefix)
		}

		objs, err := s.s3Client.ListObjectsV2(ctx, listInput)
		if err != nil {
			return fmt.Errorf("failed to list objects in bucket %s: %w", s.bucket, err)
		}

		for _, obj := range objs.Contents {
			if obj.Key == nil {
				continue
			}

			keysetName := *obj.Key

			if s.prefix != "" && len(keysetName) > len(s.prefix) {
				keysetName = keysetName[len(s.prefix):]
				if len(keysetName) > 0 && keysetName[0] == '/' {
					keysetName = keysetName[1:]
				}
			}

			if keysetName == "" {
				continue
			}

			if err := fn(keysetName); err != nil {
				return fmt.Errorf("callback function failed for S3 keyset '%s': %w", keysetName, err)
			}
		}

		if objs.IsTruncated == nil || !*objs.IsTruncated {
			break
		}

		continuationToken = objs.NextContinuationToken
	}

	return nil
}

func (s *S3Store) objectKey(keysetName string) string {
	p := s.prefix
	if p == "" {
		return keysetName
	}
	if p[len(p)-1] != '/' {
		p += "/"
	}
	return fmt.Sprintf("%s%s", p, keysetName)
}
