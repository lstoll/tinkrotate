package tinkrotate

import (
	"context"
	"fmt"
	"testing"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type ErrNotFound interface {
	error
	IsNotFoundErr()
}

type errNotFound struct{ error }

func (e *errNotFound) IsNotFoundErr()

func ErrNotFoundf(format string, args ...any) error {
	return &errNotFound{fmt.Errorf(format, args...)}
}

// type ErrNotFound struct {
// 	Message string
// 	Cause   error
// }

// func (e *ErrNotFound) Error() string {
// 	msg := e.Message
// 	if e.Cause != nil {
// 		msg += fmt.Sprintf(" (cause: %v)", e.Cause)
// 	}
// 	return msg
// }

// func (e *ErrNotFound) Unwrap() error {
// 	return e.Cause
// }

// func NotFoundErrf(cause error, format string, a ...any) error {
// 	return &ErrNotFound{
// 		Message: fmt.Sprintf(format, a...),
// 		Cause:   cause,
// 	}
// }

type Store interface {
	GetKeysetForUpdate(context.Context) (context.Context, *tinkrotatev1.Metadata, *keyset.Handle, error)
	CancelKeysetUpdate(context.Context) error
	PutKeyset(context.Context, *tinkrotatev1.Metadata, *keyset.Handle) (updated bool, _ error)
}

func test() {
	// h := &keyset.Handle{}
}

func TestStore(t testing.TB, s Store) {

}
