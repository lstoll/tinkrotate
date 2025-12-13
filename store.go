package tinkrotate

import (
	"context"
	"errors"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var (
	ErrKeysetNotFound = errors.New("keyset not found")
	ErrOptimisticLockFailed = errors.New("optimistic lock failed: keyset or metadata modified concurrently")
)

type ReadResult struct {
	Handle   *keyset.Handle
	Metadata *tinkrotatev1.KeyRotationMetadata
	Context any
}

type Store interface {
	GetCurrentHandle(ctx context.Context, keysetName string) (*keyset.Handle, error)
	GetPublicKeySetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error)
}

type ManagedStore interface {
	Store

	ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*ReadResult, error)
	WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext any) error
	ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error
}
