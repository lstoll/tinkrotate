package tinkrotate

import (
	"context"
	"errors"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var (
	// ErrKeysetNotFound indicates that the requested keyset does not exist in the store.
	ErrKeysetNotFound = errors.New("keyset not found")
	// ErrOptimisticLockFailed indicates that the write operation failed because
	// the underlying data was modified between the read and write operations.
	ErrOptimisticLockFailed = errors.New("optimistic lock failed: keyset or metadata modified concurrently")
)

// ReadResult encapsulates the data read from the store and context for optimistic locking.
type ReadResult struct {
	Handle   *keyset.Handle
	Metadata *tinkrotatev1.KeyRotationMetadata
	// Context is an opaque value used by the Store implementation for optimistic locking.
	// For SQLStore, this will typically be the version number (int64 or int).
	// For initial creation read, Context might be nil or a specific value indicating not found.
	Context interface{}
}

// Store defines the interface for persisting and retrieving Tink keysets and their rotation metadata.
// Implementations are responsible for handling potential encryption of the keyset data
// and for ensuring atomicity and preventing race conditions during writes, typically
// via optimistic locking using the Context field from ReadResult.
type Store interface {
	// ReadKeysetAndMetadata retrieves the current keyset handle and its rotation metadata.
	// If the keyset does not exist, it should return (nil, ErrKeysetNotFound).
	// It also returns an opaque Context value to be used in WriteKeysetAndMetadata for
	// optimistic locking.
	ReadKeysetAndMetadata(ctx context.Context) (*ReadResult, error)

	// WriteKeysetAndMetadata persists the given keyset handle and metadata.
	// - If expectedContext corresponds to a previous ReadResult, the write should only
	//   succeed if the underlying data hasn't changed since that read (optimistic lock).
	//   On lock failure, it must return ErrOptimisticLockFailed.
	// - If expectedContext indicates initial creation (e.g., nil or the value returned
	//   by ReadKeysetAndMetadata when ErrKeysetNotFound was returned), this performs
	//   an initial write (e.g., INSERT).
	// Implementations should handle serialization and potential encryption (using a KEK).
	WriteKeysetAndMetadata(ctx context.Context, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext interface{}) error
}
