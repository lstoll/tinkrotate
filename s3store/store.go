package s3store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	// For ETag handling
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"   // For error types like NoSuchKey
	awshttp "github.com/aws/smithy-go/transport/http" // For response error checking
	"github.com/lstoll/tinkrotate"
	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"google.golang.org/protobuf/proto"

	// Adjust import path

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var _ tinkrotate.ManagedStore = (*S3Store)(nil) // Ensure implementation

// s3StoredData is the structure persisted as a JSON object in S3.
type s3StoredData struct {
	KeysetData   []byte `json:"keyset_data"`
	MetadataData []byte `json:"metadata_data"`
}

// S3Store implements the Store interface using AWS S3.
// It stores the keyset and metadata combined in a single JSON object.
// Conditional writes are handled using S3 ETags (IfMatch / IfNoneMatch).
// NOTE: This implementation manages only a SINGLE keyset defined by the objectKey.
// The keysetName parameter in interface methods is ignored.
type S3Store struct {
	s3Client  *s3.Client
	bucket    string
	objectKey string    // The full S3 key (path) for the object
	kek       tink.AEAD // Optional: Key-Encryption-Key for the keyset handle data
}

// S3StoreOption is used to configure S3Store.
type S3StoreOption func(*S3Store)

// WithS3KEK provides a Tink AEAD primitive to encrypt/decrypt the keyset data.
func WithS3KEK(kek tink.AEAD) S3StoreOption {
	return func(s *S3Store) {
		s.kek = kek
	}
}

// NewS3Store creates a new S3Store instance.
// s3Client: An initialized *s3.Client.
// bucket: The S3 bucket name.
// objectKey: The S3 object key (path) where the data will be stored.
func NewS3Store(s3Client *s3.Client, bucket, objectKey string, opts ...S3StoreOption) (*S3Store, error) {
	if s3Client == nil {
		return nil, errors.New("s3 client cannot be nil")
	}
	if bucket == "" {
		return nil, errors.New("s3 bucket name cannot be empty")
	}
	if objectKey == "" {
		return nil, errors.New("s3 object key cannot be empty")
	}

	s := &S3Store{
		s3Client:  s3Client,
		bucket:    bucket,
		objectKey: objectKey,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// ReadKeysetAndMetadata implements the ManagedStore interface.
// NOTE: The keysetName parameter is ignored as S3Store manages a single object.
func (s *S3Store) ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*tinkrotate.ReadResult, error) {
	slog.Debug("S3Store: ReadKeysetAndMetadata called", "bucket", s.bucket, "objectKey", s.objectKey, "ignoredKeysetName", keysetName)
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey),
	}

	getObjectOutput, err := s.s3Client.GetObject(ctx, getInput)
	if err != nil {
		// Check if the error is NoSuchKey
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			// Object doesn't exist. Return NotFound error and "" context for ETag.
			// An empty ETag signals to Write that this should be an initial write.
			return &tinkrotate.ReadResult{Context: ""}, tinkrotate.ErrKeysetNotFound
		}
		// Handle other S3 errors
		return nil, fmt.Errorf("failed to get object %s/%s from S3: %w", s.bucket, s.objectKey, err)
	}
	defer getObjectOutput.Body.Close()

	// Read the object content
	objectBytes, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object body from S3: %w", err)
	}

	// Decode the JSON structure
	var stored s3StoredData
	err = json.Unmarshal(objectBytes, &stored)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal stored data JSON: %w", err)
	}

	// Parse keyset handle (assuming binary format)
	var handle *keyset.Handle
	reader := keyset.NewBinaryReader(bytes.NewReader(stored.KeysetData))
	if s.kek != nil {
		handle, err = keyset.ReadWithAssociatedData(reader, s.kek, []byte(s.objectKey))
		if err != nil {
			return nil, fmt.Errorf("failed to read keyset handle: %w", err)
		}
	} else {
		handle, err = insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read keyset handle: %w", err)
		}
	}

	// Parse metadata
	metadata := &tinkrotatev1.KeyRotationMetadata{}
	err = proto.Unmarshal(stored.MetadataData, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata protobuf: %w", err)
	}

	// Get the ETag for optimistic locking context.
	// The ETag returned by S3 includes quotes (e.g., "\"abcde12345\"").
	// The IfMatch condition in PutObject expects this quoted format.
	currentETag := ""
	if getObjectOutput.ETag != nil {
		currentETag = *getObjectOutput.ETag
	}
	if currentETag == "" {
		// Should not happen if GetObject succeeded without error, but defensive check.
		return nil, errors.New("S3 GetObject succeeded but returned an empty ETag")
	}

	return &tinkrotate.ReadResult{
		Handle:   handle,
		Metadata: metadata,
		Context:  currentETag, // Pass the ETag (with quotes) as context
	}, nil
}

// WriteKeysetAndMetadata implements the ManagedStore interface using conditional PutObject.
// NOTE: The keysetName parameter is ignored as S3Store manages a single object.
func (s *S3Store) WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext interface{}) error {
	slog.Debug("S3Store: WriteKeysetAndMetadata called", "bucket", s.bucket, "objectKey", s.objectKey, "ignoredKeysetName", keysetName)
	if handle == nil || metadata == nil {
		return errors.New("handle and metadata cannot be nil for writing")
	}

	// Determine expected ETag for optimistic locking
	var expectedETag string
	isInsert := false
	if expectedContext == nil {
		// Allow nil context for initial write, treat same as empty string ETag
		expectedETag = ""
		isInsert = true
	} else {
		etag, ok := expectedContext.(string)
		if !ok {
			return fmt.Errorf("invalid expectedContext type: expected string (ETag), got %T", expectedContext)
		}
		expectedETag = etag
		if expectedETag == "" {
			// Empty string ETag indicates the object should not exist yet (initial write)
			isInsert = true
		}
	}

	// Serialize metadata
	metadataData, err := proto.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata protobuf: %w", err)
	}

	// Serialize keyset handle (binary format)
	keysetBuf := new(bytes.Buffer)
	if s.kek != nil {
		writer := keyset.NewBinaryWriter(keysetBuf)
		err = handle.WriteWithAssociatedData(writer, s.kek, []byte(s.objectKey))
		if err != nil {
			return fmt.Errorf("failed to write keyset handle: %w", err)
		}
	} else {
		if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(keysetBuf)); err != nil {
			return fmt.Errorf("failed to write keyset handle: %w", err)
		}
	}

	// Combine into the stored data structure
	stored := s3StoredData{
		KeysetData:   keysetBuf.Bytes(),
		MetadataData: metadataData,
	}

	// Encode the combined structure to JSON
	bodyBytes, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal data for S3 object: %w", err)
	}

	// Prepare S3 PutObjectInput
	putInput := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey),
		Body:   bytes.NewReader(bodyBytes),
		// Consider setting ContentType: aws.String("application/json"),
	}

	// Set conditional headers for optimistic locking
	if isInsert {
		// For INSERT, ensure the object does NOT exist using If-None-Match: *
		putInput.IfNoneMatch = aws.String("*")
	} else {
		// For UPDATE, ensure the object exists AND its ETag matches using If-Match
		if expectedETag == "" {
			// This shouldn't happen if isInsert is false, but check defensively.
			return errors.New("invalid state: expected non-empty ETag for update operation")
		}
		// Make sure ETag includes quotes if they are expected by S3 (SDK usually handles this)
		// The ETag from GetObjectOutput includes quotes, so use it directly.
		putInput.IfMatch = aws.String(expectedETag)
	}

	// Perform the PutObject operation
	_, err = s.s3Client.PutObject(ctx, putInput)
	if err != nil {
		// Check if the error is PreconditionFailed (optimistic lock failure)
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) && responseError.HTTPStatusCode() == 412 {
			// HTTP 412 Precondition Failed indicates IfMatch or IfNoneMatch failed
			return tinkrotate.ErrOptimisticLockFailed
		}

		// Handle other S3 errors
		return fmt.Errorf("failed to put object %s/%s to S3: %w", s.bucket, s.objectKey, err)
	}

	// Success
	return nil
}

// GetCurrentHandle implements the Store interface.
// NOTE: The keysetName parameter is ignored as S3Store manages a single object.
func (s *S3Store) GetCurrentHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	slog.Debug("S3Store: GetCurrentHandle called", "bucket", s.bucket, "objectKey", s.objectKey, "ignoredKeysetName", keysetName)
	readResult, err := s.ReadKeysetAndMetadata(ctx, keysetName) // Use existing read logic
	if err != nil {
		// Map ErrKeysetNotFound correctly
		if errors.Is(err, tinkrotate.ErrKeysetNotFound) {
			return nil, fmt.Errorf("keyset '%s': %w", s.objectKey, tinkrotate.ErrKeysetNotFound)
		}
		return nil, fmt.Errorf("failed to read for GetCurrentHandle: %w", err)
	}
	if readResult.Handle == nil {
		// Should not happen if ReadKeysetAndMetadata returns nil error without ErrKeysetNotFound
		return nil, fmt.Errorf("internal error: ReadKeysetAndMetadata succeeded but returned nil handle for %s", s.objectKey)
	}
	return readResult.Handle, nil
}

// GetPublicKeySetHandle implements the Store interface.
// NOTE: The keysetName parameter is ignored as S3Store manages a single object.
func (s *S3Store) GetPublicKeySetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	slog.Debug("S3Store: GetPublicKeySetHandle called", "bucket", s.bucket, "objectKey", s.objectKey, "ignoredKeysetName", keysetName)
	fullHandle, err := s.GetCurrentHandle(ctx, keysetName)
	if err != nil {
		return nil, err // Error already includes context/wrapping
	}
	// Extract public keyset handle
	publicHandle, err := fullHandle.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public keyset handle for '%s': %w", s.objectKey, err)
	}
	return publicHandle, nil
}

// ForEachKeyset implements the ManagedStore interface.
// NOTE: Since S3Store manages only a single keyset defined by its objectKey,
// this function simply calls the callback `fn` once with the store's objectKey.
func (s *S3Store) ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error {
	slog.Debug("S3Store: ForEachKeyset called", "bucket", s.bucket, "objectKey", s.objectKey)
	// Call the function with the only keyset name this store knows about.
	err := fn(s.objectKey)
	if err != nil {
		// If the callback function returns an error, return it wrapped.
		return fmt.Errorf("callback function failed for S3 keyset '%s': %w", s.objectKey, err)
	}
	return nil
}
