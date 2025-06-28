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

// ReadResult encapsulates the data read from the store and context for optimistic locking,
// primarily used by the ManagedStore interface for rotation logic.
type ReadResult struct {
	Handle   *keyset.Handle
	Metadata *tinkrotatev1.KeyRotationMetadata
	// Context is an opaque value used by the Store implementation for optimistic locking.
	// For SQLStore, this will typically be the version number (int64 or int).
	// For initial creation read, Context might be nil or a specific value indicating not found.
	Context any
}

// Store defines the interface for retrieving Tink keyset handles.
// This is intended for consumers that need to use the keysets (e.g., for encryption/decryption).
type Store interface {
	// GetCurrentHandle retrieves the current *full* keyset handle (including private key
	// material) for the specified keyset name. Returns ErrKeysetNotFound if the
	// keyset doesn't exist.
	GetCurrentHandle(ctx context.Context, keysetName string) (*keyset.Handle, error)

	// GetPublicKeySetHandle retrieves the public keyset handle for the specified keyset name.
	// This is safer for distribution as it does not contain private key material.
	// Returns ErrKeysetNotFound if the keyset doesn't exist.
	GetPublicKeySetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error)
}

// ManagedStore extends the Store interface with methods required for keyset management
// and rotation, including reading/writing metadata and iterating over keysets.
// This interface is typically used by the AutoRotator.
type ManagedStore interface {
	Store // Embed the read-only Store interface

	// ReadKeysetAndMetadata retrieves the current keyset handle and its rotation metadata
	// for the specified keyset name.
	// If the keyset does not exist, it should return (nil, ErrKeysetNotFound).
	// It also returns an opaque Context value to be used in WriteKeysetAndMetadata for
	// optimistic locking.
	ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*ReadResult, error)

	// WriteKeysetAndMetadata persists the given keyset handle and metadata for the specified
	// keyset name.
	// - If expectedContext corresponds to a previous ReadResult, the write should only
	//   succeed if the underlying data hasn't changed since that read (optimistic lock).
	//   On lock failure, it must return ErrOptimisticLockFailed.
	// - If expectedContext indicates initial creation (e.g., nil or the value returned
	//   by ReadKeysetAndMetadata when ErrKeysetNotFound was returned), this performs
	//   an initial write (e.g., INSERT).
	// Implementations should handle serialization and potential encryption (using a KEK).
	WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext any) error

	// ForEachKeyset iterates over all known keyset names in the store and calls
	// the provided function `fn` for each keyset name. If `fn` returns an error,
	// the iteration stops and the error is returned. Implementations may choose
	// to perform iteration in batches for efficiency.
	ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error
}
