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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AutoRotator manages the lifecycle of Tink keysets within a store, performing
// automatic rotation based on a schedule and policy.
type AutoRotator struct {
	store         ManagedStore
	rotator       *Rotator
	checkInterval time.Duration
	// Removed keyTemplate as provisioning now happens per-keyset if needed

	// Background routine management
	// Use a mutex to protect access to background routine state variables
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}      // Signals the background goroutine to stop
	shutdownWg sync.WaitGroup     // Waits for the background goroutine to finish
	cancelCtx  context.CancelFunc // Cancels the context used by the background routine

	// Optional: Specific keyset names to ensure are processed by RunOnce, even if not found by ForEachKeyset initially.
	targetKeysetNames []string
}

// AutoRotatorOption allows configuring the AutoRotator.
type AutoRotatorOption func(*AutoRotator)

// WithTargetKeysetNames sets specific keyset names that RunOnce should always attempt to process.
func WithTargetKeysetNames(names ...string) AutoRotatorOption {
	return func(ar *AutoRotator) {
		ar.targetKeysetNames = names
	}
}

// NewAutoRotator creates a new AutoRotator.
// store: The persistence layer implementation.
// rotator: The core rotation logic implementation.
// checkInterval: How often to check if rotation is needed.
// opts: Optional configuration settings.
func NewAutoRotator(store ManagedStore, rotator *Rotator, checkInterval time.Duration, opts ...AutoRotatorOption) (*AutoRotator, error) {
	if store == nil {
		return nil, errors.New("store cannot be nil")
	}
	if rotator == nil {
		return nil, errors.New("rotator cannot be nil")
	}
	if checkInterval <= 0 {
		return nil, errors.New("checkInterval must be positive")
	}

	ar := &AutoRotator{
		store:         store,
		rotator:       rotator,
		checkInterval: checkInterval,
		// keyTemplate removed
		running: false,
	}

	for _, opt := range opts {
		opt(ar)
	}

	return ar, nil
}

// RunOnce performs a single check-and-rotate cycle for all keysets found in the store.
// It iterates through each keyset name provided by store.ForEachKeyset.
// For each keyset, it reads the current state, provisions if necessary (using the rotator's policy template),
// performs rotation logic, checks if changes occurred, and writes the updated
// state back to the store only if needed.
func (ar *AutoRotator) RunOnce(ctx context.Context) error {
	log.Println("AutoRotator: Starting rotation check cycle for all keysets...")
	var firstError error                       // Keep track of the first error encountered
	processedKeys := make(map[string]struct{}) // Track keys processed via ForEachKeyset

	// Process keys found in the store
	err := ar.store.ForEachKeyset(ctx, func(keysetName string) error {
		log.Printf("AutoRotator: Processing existing keyset '%s' found via ForEachKeyset...", keysetName)
		processedKeys[keysetName] = struct{}{}
		runErr := ar.processSingleKeyset(ctx, keysetName)
		if runErr != nil {
			log.Printf("AutoRotator: Error processing keyset '%s': %v", keysetName, runErr)
			if firstError == nil {
				firstError = fmt.Errorf("error processing keyset '%s': %w", keysetName, runErr)
			}
		}
		return nil // Continue iteration even if one keyset fails
	})

	if err != nil {
		// This error comes from ForEachKeyset itself (e.g., failed DB connection)
		if firstError == nil {
			firstError = fmt.Errorf("failed iterating keysets in store: %w", err)
		} else {
			// Log this error too, but prioritize the error from processSingleKeyset
			log.Printf("AutoRotator: Error iterating keysets in store: %v", err)
		}
	}

	// Process target keyset names that weren't found by ForEachKeyset
	for _, targetName := range ar.targetKeysetNames {
		if _, alreadyProcessed := processedKeys[targetName]; !alreadyProcessed {
			log.Printf("AutoRotator: Processing target keyset '%s' (not found by ForEachKeyset)...", targetName)
			runErr := ar.processSingleKeyset(ctx, targetName)
			if runErr != nil {
				log.Printf("AutoRotator: Error processing target keyset '%s': %v", targetName, runErr)
				if firstError == nil {
					firstError = fmt.Errorf("error processing target keyset '%s': %w", targetName, runErr)
				}
			}
		}
	}

	log.Println("AutoRotator: Finished rotation check cycle.")
	return firstError // Return the first error encountered, if any
}

// processSingleKeyset handles the read, provision/rotate, and write logic for one keyset.
func (ar *AutoRotator) processSingleKeyset(ctx context.Context, keysetName string) error {
	// Use the keyTemplate from the rotator's policy for potential provisioning
	keyTemplate := ar.rotator.Policy.KeyTemplate
	if keyTemplate == nil {
		return fmt.Errorf("rotator policy keyTemplate is nil, cannot provision keyset '%s'", keysetName)
	}

	readResult, err := ar.store.ReadKeysetAndMetadata(ctx, keysetName) // Pass keysetName

	if err != nil && !errors.Is(err, ErrKeysetNotFound) {
		return fmt.Errorf("failed to read from store for keyset '%s': %w", keysetName, err)
	}

	var currentHandle *keyset.Handle
	var currentMetadata *tinkrotatev1.KeyRotationMetadata
	var originalMetadataClone proto.Message // Store original for comparison
	var currentContext interface{}
	isInitialProvisioning := false

	if errors.Is(err, ErrKeysetNotFound) {
		// --- Provision Initial Keyset ---
		log.Printf("AutoRotator: Keyset '%s' not found, provisioning initial keyset...", keysetName)
		isInitialProvisioning = true
		if readResult != nil { // Get context even on ErrKeysetNotFound
			currentContext = readResult.Context
		}

		manager := keyset.NewManager()
		keyID, err := manager.Add(keyTemplate) // Use template from policy
		if err != nil {
			return fmt.Errorf("failed to add initial key using template for keyset '%s': %w", keysetName, err)
		}
		err = manager.SetPrimary(keyID)
		if err != nil {
			return fmt.Errorf("failed to set initial primary key for keyset '%s': %w", keysetName, err)
		}
		currentHandle, err = manager.Handle()
		if err != nil {
			return fmt.Errorf("failed to get initial handle for keyset '%s': %w", keysetName, err)
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
		log.Printf("AutoRotator: Provisioned initial keyset '%s' with key ID %d", keysetName, keyID)

	} else {
		// --- Keyset Exists ---
		currentHandle = readResult.Handle
		currentMetadata = readResult.Metadata
		currentContext = readResult.Context
		// Clone the original metadata *before* passing it to the rotator
		originalMetadataClone = proto.Clone(currentMetadata)
		log.Printf("AutoRotator: Read keyset '%s' version %v from store.", keysetName, currentContext)
	}

	// --- Perform Rotation Logic ---
	metadataForRotator := currentMetadata

	newHandle, newMetadata, rotationErr := ar.rotator.RotateKeyset(currentHandle, metadataForRotator)
	if rotationErr != nil {
		return fmt.Errorf("rotation logic failed for keyset '%s': %w", keysetName, rotationErr)
	}

	// --- Check if Changes Occurred ---
	metadataChanged := true // Assume changed if it was initial provisioning
	keysetChanged := true   // Assume changed if it was initial provisioning

	if !isInitialProvisioning {
		metadataChanged = !proto.Equal(originalMetadataClone, newMetadata)
		keysetChanged = !proto.Equal(currentHandle.KeysetInfo(), newHandle.KeysetInfo())
	}

	// --- Write Back to Store (Only If Changed) ---
	if !metadataChanged && !keysetChanged {
		log.Printf("AutoRotator: No changes detected for keyset '%s', skipping write.", keysetName)
		return nil
	}

	log.Printf("AutoRotator: Changes detected for keyset '%s' (MetadataChanged: %t, KeysetChanged: %t). Attempting to write updated state (expected context: %v)...",
		keysetName, metadataChanged, keysetChanged, currentContext)
	// Pass keysetName to WriteKeysetAndMetadata
	writeErr := ar.store.WriteKeysetAndMetadata(ctx, keysetName, newHandle, newMetadata, currentContext)

	if writeErr != nil {
		if errors.Is(writeErr, ErrOptimisticLockFailed) {
			log.Printf("AutoRotator: Optimistic lock failed during write for keyset '%s', another process may have updated concurrently.", keysetName)
			// Treat lock failure as non-fatal for this specific keyset, let next cycle retry
			return nil
		}
		return fmt.Errorf("failed to write updated state to store for keyset '%s': %w", keysetName, writeErr)
	}

	log.Printf("AutoRotator: Successfully updated state for keyset '%s' in store.", keysetName)
	return nil
}

// Start begins the background rotation routine.
// It's safe to call Start multiple times; it will only start if not already running.
// The provided context governs the lifetime of the background routine.
// The routine will periodically call RunOnce to process all keysets.
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
			// Log the error from the initial full run, but don't stop the ticker
			log.Printf("AutoRotator: Error during initial run cycle: %v", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := ar.RunOnce(runCtx); err != nil {
					// Log errors from periodic full runs but continue
					log.Printf("AutoRotator: Error during periodic run cycle: %v", err)
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
	ar.mu.Unlock() // Unlock before waiting

	log.Println("AutoRotator: Waiting for background routine to shut down...")
	ar.shutdownWg.Wait() // Wait for the goroutine to finish
	ar.mu.Lock()         // Re-acquire lock to safely update running status
	ar.running = false
	ar.cancelCtx = nil // Clean up cancel func
	ar.mu.Unlock()
	log.Println("AutoRotator: Background routine shut down successfully.")
}
