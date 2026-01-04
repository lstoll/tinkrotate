package tinkrotate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type mockStore struct {
	calls  []string
	handle *keyset.Handle
	err    error
}

func (m *mockStore) GetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	m.calls = append(m.calls, keysetName)
	if ctx.Value(testContextKey{}) == "value" {
		m.calls = append(m.calls, "ctx_found")
	}
	return m.handle, m.err
}

func (m *mockStore) GetPublicHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	return nil, errors.New("not implemented")
}

func TestPrimitiveSource_AEAD_Caching(t *testing.T) {
	// Setup handle
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	ms := &mockStore{handle: kh}

	// Short TTL for testing
	ttl := 100 * time.Millisecond
	source := NewPrimitiveSource(ms, ttl)

	primitive, err := source.GetAEAD("test-keyset")
	if err != nil {
		t.Fatal(err)
	}

	// 1. First call triggers fetch
	_, err = primitive.Encrypt([]byte("foo"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ms.calls) != 1 {
		t.Errorf("expected 1 call, got %d", len(ms.calls))
	}

	// 2. Second call within TTL should be cached
	_, err = primitive.Encrypt([]byte("bar"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ms.calls) != 1 {
		t.Errorf("expected 1 call (cached), got %d", len(ms.calls))
	}

	// 3. Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// 4. Third call triggers refresh
	_, err = primitive.Encrypt([]byte("baz"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(ms.calls) != 2 {
		t.Errorf("expected 2 calls, got %d", len(ms.calls))
	}
}

type testContextKey struct{}

func TestPrimitiveSource_Context(t *testing.T) {
	// Setup handle
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	ms := &mockStore{handle: kh}
	source := NewPrimitiveSource(ms, time.Minute)

	primitive, err := source.GetAEAD("test-keyset")
	if err != nil {
		t.Fatal(err)
	}

	// Bind context
	ctx := context.WithValue(context.Background(), testContextKey{}, "value")
	// The WithContext returns ContextBoundAEAD, so we can cast back to call Encrypt if we wanted,
	// but Encrypt is part of AEAD interface.
	// However, we want to ensure the bound primitive uses the context.
	boundPrimitive := primitive.WithContext(ctx)

	// Trigger fetch
	_, err = boundPrimitive.Encrypt([]byte("foo"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check if context was passed
	found := false
	for _, c := range ms.calls {
		if c == "ctx_found" {
			found = true
		}
	}
	if !found {
		t.Error("context value not found in mock store calls")
	}
}

func TestPrimitiveSource_SignerVerifier(t *testing.T) {
	// Setup handle for signature
	kh, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatal(err)
	}

	ms := &mockStore{handle: kh}
	source := NewPrimitiveSource(ms, time.Minute)

	signer, err := source.GetSigner("jwt-keyset")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := source.GetVerifier("jwt-keyset")
	if err != nil {
		t.Fatal(err)
	}

	// Sign
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatal(err)
	}

	token, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatal(err)
	}

	if len(ms.calls) != 1 {
		t.Errorf("expected 1 call for signer, got %d", len(ms.calls))
	}

	// Verify
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatal(err)
	}

	_, err = verifier.VerifyAndDecode(token, validator)
	if err != nil {
		t.Fatal(err)
	}

	// Verify triggers another fetch (different provider instance)
	// But wait, GetSigner and GetVerifier create NEW providers.
	// So ms.calls should be 2.
	if len(ms.calls) != 2 {
		t.Errorf("expected 2 calls (1 signer, 1 verifier), got %d", len(ms.calls))
	}
}
