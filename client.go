package tinkrotate

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// DefaultCacheTTL is the default duration to cache keyset handles.
const DefaultCacheTTL = 5 * time.Minute

// PrimitiveSource creates Tink primitives that are backed by a managed store.
// These primitives automatically refresh their underlying keyset handles from the store
// based on a cache TTL.
type PrimitiveSource struct {
	store    Store
	cacheTTL time.Duration
}

// NewPrimitiveSource creates a new source. If cacheTTL is <= 0, DefaultCacheTTL is used.
func NewPrimitiveSource(store Store, cacheTTL time.Duration) *PrimitiveSource {
	if cacheTTL <= 0 {
		cacheTTL = DefaultCacheTTL
	}
	return &PrimitiveSource{
		store:    store,
		cacheTTL: cacheTTL,
	}
}

// GetAEAD returns a dynamic tink.AEAD backed by the named keyset.
func (f *PrimitiveSource) GetAEAD(keysetName string) (ContextBoundAEAD, error) {
	hp := newHandleProvider(f.store, keysetName, f.cacheTTL)
	return &dynamicAEAD{hp: hp}, nil
}

// GetSigner returns a dynamic jwt.Signer backed by the named keyset.
func (f *PrimitiveSource) GetSigner(keysetName string) (ContextBoundSigner, error) {
	hp := newHandleProvider(f.store, keysetName, f.cacheTTL)
	return &dynamicSigner{hp: hp}, nil
}

// GetVerifier returns a dynamic jwt.Verifier backed by the named keyset.
func (f *PrimitiveSource) GetVerifier(keysetName string) (ContextBoundVerifier, error) {
	hp := newHandleProvider(f.store, keysetName, f.cacheTTL)
	return &dynamicVerifier{hp: hp}, nil
}

// GetMAC returns a dynamic tink.MAC backed by the named keyset.
func (f *PrimitiveSource) GetMAC(keysetName string) (ContextBoundMAC, error) {
	hp := newHandleProvider(f.store, keysetName, f.cacheTTL)
	return &dynamicMAC{hp: hp}, nil
}

// handleProvider manages the caching and retrieval of a keyset handle.
type handleProvider struct {
	store      Store
	keysetName string
	ttl        time.Duration

	mu          sync.RWMutex
	handle      *keyset.Handle
	lastUpdated time.Time
}

func newHandleProvider(store Store, keysetName string, ttl time.Duration) *handleProvider {
	return &handleProvider{
		store:      store,
		keysetName: keysetName,
		ttl:        ttl,
	}
}

func (hp *handleProvider) getHandle(ctx context.Context) (*keyset.Handle, error) {
	hp.mu.RLock()
	// Check if we have a valid cached handle
	if hp.handle != nil && time.Since(hp.lastUpdated) < hp.ttl {
		h := hp.handle
		hp.mu.RUnlock()
		return h, nil
	}
	hp.mu.RUnlock()

	hp.mu.Lock()
	defer hp.mu.Unlock()

	// Double-check locking
	if hp.handle != nil && time.Since(hp.lastUpdated) < hp.ttl {
		return hp.handle, nil
	}

	// Fetch from store
	// If ctx is nil, we use Background, but caller should provide one if they care about cancellation/tracing.
	fetchCtx := ctx
	if fetchCtx == nil {
		fetchCtx = context.Background()
	}

	h, err := hp.store.GetHandle(fetchCtx, hp.keysetName)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh keyset handle: %w", err)
	}

	hp.handle = h
	hp.lastUpdated = time.Now()
	return h, nil
}

// --- AEAD ---

// ContextBoundAEAD extends tink.AEAD to allow binding a context for internal operations.
type ContextBoundAEAD interface {
	tink.AEAD
	WithContext(ctx context.Context) ContextBoundAEAD
}

type dynamicAEAD struct {
	hp  *handleProvider
	ctx context.Context // Context used for handle refreshes
}

func (d *dynamicAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	h, err := d.hp.getHandle(d.ctx)
	if err != nil {
		return nil, err
	}
	// TODO: Consider caching the primitive itself if the handle hasn't changed.
	// For now, AEAD creation is relatively cheap.
	a, err := aead.New(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD primitive: %w", err)
	}
	return a.Encrypt(plaintext, associatedData)
}

func (d *dynamicAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	h, err := d.hp.getHandle(d.ctx)
	if err != nil {
		return nil, err
	}
	a, err := aead.New(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD primitive: %w", err)
	}
	return a.Decrypt(ciphertext, associatedData)
}

func (d *dynamicAEAD) WithContext(ctx context.Context) ContextBoundAEAD {
	return &dynamicAEAD{
		hp:  d.hp,
		ctx: ctx,
	}
}

// --- JWT Signer ---

type ContextBoundSigner interface {
	jwt.Signer
	WithContext(ctx context.Context) ContextBoundSigner
}

type dynamicSigner struct {
	hp  *handleProvider
	ctx context.Context
}

func (d *dynamicSigner) SignAndEncode(rawJWT *jwt.RawJWT) (string, error) {
	h, err := d.hp.getHandle(d.ctx)
	if err != nil {
		return "", err
	}
	s, err := jwt.NewSigner(h)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT Signer: %w", err)
	}
	return s.SignAndEncode(rawJWT)
}

func (d *dynamicSigner) WithContext(ctx context.Context) ContextBoundSigner {
	return &dynamicSigner{
		hp:  d.hp,
		ctx: ctx,
	}
}

// --- JWT Verifier ---

type ContextBoundVerifier interface {
	jwt.Verifier
	WithContext(ctx context.Context) ContextBoundVerifier
}

type dynamicVerifier struct {
	hp  *handleProvider
	ctx context.Context
}

func (d *dynamicVerifier) VerifyAndDecode(token string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	h, err := d.hp.getHandle(d.ctx)
	if err != nil {
		return nil, err
	}
	// Try to get the public keyset handle. jwt.NewVerifier requires a public keyset handle.
	// If the handle is already public (or symmetric), h.Public() returns an error, so we use h as is.
	if pubH, err := h.Public(); err == nil {
		h = pubH
	}
	v, err := jwt.NewVerifier(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT Verifier: %w", err)
	}
	return v.VerifyAndDecode(token, validator)
}

func (d *dynamicVerifier) WithContext(ctx context.Context) ContextBoundVerifier {
	return &dynamicVerifier{
		hp:  d.hp,
		ctx: ctx,
	}
}

// --- MAC ---

type ContextBoundMAC interface {
	tink.MAC
	WithContext(ctx context.Context) ContextBoundMAC
}

type dynamicMAC struct {
	hp  *handleProvider
	ctx context.Context
}

func (d *dynamicMAC) ComputeMAC(data []byte) ([]byte, error) {
	h, err := d.hp.getHandle(d.ctx)
	if err != nil {
		return nil, err
	}
	m, err := mac.New(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create MAC primitive: %w", err)
	}
	return m.ComputeMAC(data)
}

func (d *dynamicMAC) VerifyMAC(macBytes, data []byte) error {
	h, err := d.hp.getHandle(d.ctx)
	if err != nil {
		return err
	}
	m, err := mac.New(h)
	if err != nil {
		return fmt.Errorf("failed to create MAC primitive: %w", err)
	}
	return m.VerifyMAC(macBytes, data)
}

func (d *dynamicMAC) WithContext(ctx context.Context) ContextBoundMAC {
	return &dynamicMAC{
		hp:  d.hp,
		ctx: ctx,
	}
}
