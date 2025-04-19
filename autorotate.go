package tinkrotate

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AutoRotator manages the lifecycle of a Tink keyset, performing automatic rotation
// based on a schedule and policy, using a Store for persistence.
type AutoRotator struct {
	store         Store
	rotator       *Rotator // The logic rotator
	checkInterval time.Duration
	keyTemplate   *tinkpb.KeyTemplate // Template for initial keyset provisioning

	// Background routine management
	// Use a mutex to protect access to background routine state variables
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}      // Signals the background goroutine to stop
	shutdownWg sync.WaitGroup     // Waits for the background goroutine to finish
	cancelCtx  context.CancelFunc // Cancels the context used by the background routine
}

// AutoRotatorOption allows configuring the AutoRotator.
type AutoRotatorOption func(*AutoRotator)

// NewAutoRotator creates a new AutoRotator.
// store: The persistence layer implementation.
// rotator: The core rotation logic implementation.
// checkInterval: How often to check if rotation is needed.
// keyTemplate: The template used ONLY for creating the very first keyset if none exists.
// opts: Optional configuration settings.
func NewAutoRotator(store Store, rotator *Rotator, checkInterval time.Duration, keyTemplate *tinkpb.KeyTemplate, opts ...AutoRotatorOption) (*AutoRotator, error) {
	if store == nil {
		return nil, errors.New("store cannot be nil")
	}
	if rotator == nil {
		return nil, errors.New("rotator cannot be nil")
	}
	if checkInterval <= 0 {
		return nil, errors.New("checkInterval must be positive")
	}
	if keyTemplate == nil {
		return nil, errors.New("keyTemplate cannot be nil (needed for initial provisioning)")
	}

	ar := &AutoRotator{
		store:         store,
		rotator:       rotator,
		checkInterval: checkInterval,
		keyTemplate:   keyTemplate,
		running:       false,
	}

	for _, opt := range opts {
		opt(ar)
	}

	return ar, nil
}

// RunOnce performs a single check-and-rotate cycle.
// It reads the current state from the store, provisions a keyset if necessary,
// performs rotation logic, checks if changes occurred, and writes the updated
// state back to the store only if needed.
func (ar *AutoRotator) RunOnce(ctx context.Context) error {
	log.Println("AutoRotator: Running rotation check...")

	readResult, err := ar.store.ReadKeysetAndMetadata(ctx)

	if err != nil && !errors.Is(err, ErrKeysetNotFound) {
		return fmt.Errorf("failed to read from store: %w", err)
	}

	var currentHandle *keyset.Handle
	var currentMetadata *tinkrotatev1.KeyRotationMetadata
	var originalMetadataClone proto.Message // Store original for comparison
	var currentContext interface{}
	isInitialProvisioning := false

	if errors.Is(err, ErrKeysetNotFound) {
		// --- Provision Initial Keyset ---
		log.Println("AutoRotator: Keyset not found, provisioning initial keyset...")
		isInitialProvisioning = true
		currentContext = readResult.Context // Should be context indicating not found (e.g., version 0)

		manager := keyset.NewManager()
		keyID, err := manager.Add(ar.keyTemplate)
		if err != nil {
			return fmt.Errorf("failed to add initial key using template: %w", err)
		}
		err = manager.SetPrimary(keyID)
		if err != nil {
			return fmt.Errorf("failed to set initial primary key: %w", err)
		}
		currentHandle, err = manager.Handle()
		if err != nil {
			return fmt.Errorf("failed to get initial handle: %w", err)
		}

		now := ar.rotator.now()
		currentMetadata = &tinkrotatev1.KeyRotationMetadata{
			KeyMetadata: map[uint32]*tinkrotatev1.KeyMetadata{
				keyID: {
					KeyId:         keyID,
					State:         tinkrotatev1.KeyState_KEY_STATE_PRIMARY,
					CreationTime:  timestamppb.New(now),
					PromotionTime: timestamppb.New(now),
				},
			},
		}
		// No originalMetadataClone needed as we definitely need to write
		log.Printf("AutoRotator: Provisioned initial keyset with key ID %d", keyID)

	} else {
		// --- Keyset Exists ---
		currentHandle = readResult.Handle
		currentMetadata = readResult.Metadata
		currentContext = readResult.Context
		// Clone the original metadata *before* passing it to the rotator
		originalMetadataClone = proto.Clone(currentMetadata)
		log.Printf("AutoRotator: Read keyset version %v from store.", currentContext)
	}

	// --- Perform Rotation Logic ---
	// Make a defensive copy of the metadata map reference in case the rotator modifies the map structure itself,
	// although modifying the contained messages is more likely. Cloning above handles message changes.
	metadataForRotator := currentMetadata // Usually okay unless rotator replaces the map itself

	newHandle, newMetadata, rotationErr := ar.rotator.RotateKeyset(currentHandle, metadataForRotator)
	if rotationErr != nil {
		return fmt.Errorf("rotation logic failed: %w", rotationErr)
	}

	// --- Check if Changes Occurred ---
	metadataChanged := true // Assume changed if it was initial provisioning
	keysetChanged := true   // Assume changed if it was initial provisioning

	if !isInitialProvisioning {
		// Compare metadata using proto.Equal
		metadataChanged = !proto.Equal(originalMetadataClone, newMetadata)

		// Compare keysets using KeysetInfo (proto.Equal)
		keysetChanged = !proto.Equal(currentHandle.KeysetInfo(), newHandle.KeysetInfo())

		// --- Alternative Keyset Comparison (Serialization - more definitive but slower) ---
		/*
			keysetChanged, err = compareHandlesSerialization(currentHandle, newHandle)
			if err != nil {
				return fmt.Errorf("failed to compare keyset handles: %w", err)
			}
		*/
	}

	// --- Write Back to Store (Only If Changed) ---
	if !metadataChanged && !keysetChanged {
		log.Println("AutoRotator: No changes detected by rotator, skipping write.")
		return nil
	}

	log.Printf("AutoRotator: Changes detected (MetadataChanged: %t, KeysetChanged: %t). Attempting to write updated state (expected context: %v)...",
		metadataChanged, keysetChanged, currentContext)
	writeErr := ar.store.WriteKeysetAndMetadata(ctx, newHandle, newMetadata, currentContext)

	if writeErr != nil {
		if errors.Is(writeErr, ErrOptimisticLockFailed) {
			log.Println("AutoRotator: Optimistic lock failed during write, another process may have updated concurrently.")
			return nil // Expected condition, let next cycle retry
		}
		return fmt.Errorf("failed to write updated state to store: %w", writeErr)
	}

	log.Println("AutoRotator: Successfully updated state in store.")
	return nil
}

// Start begins the background rotation routine.
// It's safe to call Start multiple times; it will only start if not already running.
// The provided context governs the lifetime of the background routine.
func (ar *AutoRotator) Start(ctx context.Context) {
	ar.mu.Lock()
	if ar.running {
		ar.mu.Unlock()
		log.Println("AutoRotator: Background routine already running.")
		return
	}

	// Create context that can be cancelled by Stop()
	runCtx, cancel := context.WithCancel(ctx)
	ar.cancelCtx = cancel

	ar.running = true
	ar.stopChan = make(chan struct{})
	ar.shutdownWg.Add(1)
	ar.mu.Unlock()

	log.Println("AutoRotator: Starting background rotation routine...")

	go func() {
		defer ar.shutdownWg.Done()
		ticker := time.NewTicker(ar.checkInterval)
		defer ticker.Stop()

		log.Println("AutoRotator: Background routine started.")

		// Run once immediately on start
		if err := ar.RunOnce(runCtx); err != nil {
			log.Printf("AutoRotator: Error during initial run: %v", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := ar.RunOnce(runCtx); err != nil {
					// Log errors from periodic runs but continue
					log.Printf("AutoRotator: Error during periodic run: %v", err)
				}
			case <-ar.stopChan:
				log.Println("AutoRotator: Received stop signal, background routine shutting down.")
				return
			case <-runCtx.Done():
				log.Println("AutoRotator: Context cancelled, background routine shutting down.")
				return // Exit if the parent context is cancelled
			}
		}
	}()
}

// Stop signals the background rotation routine to stop gracefully and waits for it to exit.
func (ar *AutoRotator) Stop() {
	ar.mu.Lock()
	if !ar.running {
		ar.mu.Unlock()
		log.Println("AutoRotator: Stop called but background routine was not running.")
		return
	}

	log.Println("AutoRotator: Signaling background routine to stop...")
	close(ar.stopChan) // Signal the goroutine to stop

	// Cancel the context associated with the run to interrupt any pending operations
	if ar.cancelCtx != nil {
		ar.cancelCtx()
	}

	ar.running = false
	ar.mu.Unlock() // Unlock before waiting

	log.Println("AutoRotator: Waiting for background routine to shut down...")
	ar.shutdownWg.Wait() // Wait for the goroutine to finish
	log.Println("AutoRotator: Background routine shut down complete.")
}
