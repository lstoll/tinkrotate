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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrKeysetExists indicates that an attempt was made to provision a keyset that already exists.
var ErrKeysetExists = errors.New("keyset already exists")

// ErrRotationPolicyMissing indicates the metadata lacks a required rotation policy.
var ErrRotationPolicyMissing = errors.New("rotation policy missing in metadata")

// AutoRotatorOpts provides optional configuration for the AutoRotator.
type AutoRotatorOpts struct {
	// ProvisionPolicies specifies a map of keyset names to their desired rotation
	// policies. If a keyset name listed here does not exist in the store when
	// RunOnce executes, the AutoRotator will attempt to provision it using the
	// provided policy.
	ProvisionPolicies map[string]*tinkrotatev1.RotationPolicy
}

// AutoRotator manages the lifecycle of Tink keysets within a store, performing
// automatic rotation based on a schedule and the policies defined within each keyset's metadata.
// It can also ensure specific keysets are provisioned if they don't exist.
type AutoRotator struct {
	store             ManagedStore
	checkInterval     time.Duration
	now               func() time.Time                        // Allow mocking time
	provisionPolicies map[string]*tinkrotatev1.RotationPolicy // Store policies to provision

	// Background routine management
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
	shutdownWg sync.WaitGroup
	cancelCtx  context.CancelFunc
}

// NewAutoRotator creates a new AutoRotator.
// store: The persistence layer implementation.
// checkInterval: How often to check if rotation is needed.
// opts: Optional configuration, including policies for keysets to provision.
func NewAutoRotator(store ManagedStore, checkInterval time.Duration, opts *AutoRotatorOpts) (*AutoRotator, error) {
	if store == nil {
		return nil, errors.New("store cannot be nil")
	}
	if checkInterval <= 0 {
		return nil, errors.New("checkInterval must be positive")
	}

	// Validate policies within opts before creating the AutoRotator
	provisionPolicies := make(map[string]*tinkrotatev1.RotationPolicy)
	if opts != nil && opts.ProvisionPolicies != nil {
		for name, policy := range opts.ProvisionPolicies {
			if err := ValidateRotationPolicy(policy); err != nil {
				return nil, fmt.Errorf("invalid policy provided in ProvisionPolicies for keyset '%s': %w", name, err)
			}
			provisionPolicies[name] = policy // Store validated policy
		}
	}

	ar := &AutoRotator{
		store:             store,
		checkInterval:     checkInterval,
		now:               time.Now,          // Default to real time
		provisionPolicies: provisionPolicies, // Assign validated map
		running:           false,
	}

	return ar, nil
}

// RunOnce performs a single check-and-rotate cycle for all keysets found in the store.
// It iterates through each keyset name provided by store.ForEachKeyset.
// It reads each keyset, applies the rotation logic defined in its *own* metadata,
// and writes back if changes occurred.
// After processing existing keysets, it checks the keys specified in ProvisionPolicies
// (from opts) and attempts to provision any that do not exist in the store.
func (ar *AutoRotator) RunOnce(ctx context.Context) error {
	log.Println("AutoRotator: Starting rotation check cycle...")
	var firstError error
	processedKeys := make(map[string]struct{}) // Track keys processed by ForEachKeyset

	// 1. Process existing keys found in the store
	log.Println("AutoRotator: Processing existing keysets found in store...")
	err := ar.store.ForEachKeyset(ctx, func(keysetName string) error {
		log.Printf("AutoRotator: Processing existing keyset '%s'...", keysetName)
		processedKeys[keysetName] = struct{}{} // Mark as processed
		runErr := ar.processSingleKeyset(ctx, keysetName)
		if runErr != nil {
			log.Printf("AutoRotator: Error processing keyset '%s': %v", keysetName, runErr)
			if firstError == nil {
				// Capture the first error encountered during rotation of existing keys
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

	// 2. Process keys specified for provisioning if they weren't already processed
	if len(ar.provisionPolicies) > 0 {
		log.Println("AutoRotator: Checking specified keysets for provisioning...")
		for keysetName, policy := range ar.provisionPolicies {
			if _, alreadyProcessed := processedKeys[keysetName]; alreadyProcessed {
				log.Printf("AutoRotator: Keyset '%s' already processed, skipping provisioning check.", keysetName)
				continue
			}

			log.Printf("AutoRotator: Checking existence of specified keyset '%s' for potential provisioning...", keysetName)
			// Check if it exists now. We expect ErrKeysetNotFound if we need to provision.
			_, readErr := ar.store.ReadKeysetAndMetadata(ctx, keysetName)

			if readErr == nil {
				// Keyset exists unexpectedly (ForEachKeyset might be inconsistent or timing issue)
				log.Printf("AutoRotator: Specified keyset '%s' found unexpectedly, skipping provisioning.", keysetName)
				continue
			}

			if errors.Is(readErr, ErrKeysetNotFound) {
				// Keyset does not exist, attempt to provision it
				log.Printf("AutoRotator: Attempting to provision specified keyset '%s'...", keysetName)
				provisionErr := ar.ProvisionKeyset(ctx, keysetName, policy)
				if provisionErr != nil {
					log.Printf("AutoRotator: Failed to provision specified keyset '%s': %v", keysetName, provisionErr)
					if firstError == nil {
						// Capture the first provisioning error
						firstError = fmt.Errorf("failed to provision specified keyset '%s': %w", keysetName, provisionErr)
					}
				} else {
					log.Printf("AutoRotator: Successfully provisioned specified keyset '%s'.", keysetName)
				}
			} else {
				// Another error occurred trying to read the keyset
				log.Printf("AutoRotator: Error checking existence of specified keyset '%s' for provisioning: %v", keysetName, readErr)
				if firstError == nil {
					firstError = fmt.Errorf("error checking existence of specified keyset '%s': %w", keysetName, readErr)
				}
			}
		}
	}

	log.Println("AutoRotator: Finished rotation check cycle.")
	return firstError // Return the first error encountered, if any
}

// processSingleKeyset handles the read, rotate, and write logic for one keyset.
// It expects the keyset to exist and have valid metadata including a rotation policy.
func (ar *AutoRotator) processSingleKeyset(ctx context.Context, keysetName string) error {
	readResult, err := ar.store.ReadKeysetAndMetadata(ctx, keysetName)

	if err != nil {
		if errors.Is(err, ErrKeysetNotFound) {
			// This should ideally not happen if ForEachKeyset is consistent,
			// but handle it gracefully. RunOnce doesn't provision.
			log.Printf("AutoRotator: Keyset '%s' not found during processing (skipped).", keysetName)
			return nil // Not an error for RunOnce, just skip.
		}
		// Other read errors are fatal for this keyset
		return fmt.Errorf("failed to read from store for keyset '%s': %w", keysetName, err)
	}

	// --- Keyset Exists ---
	currentHandle := readResult.Handle
	currentMetadata := readResult.Metadata
	currentContext := readResult.Context

	if currentHandle == nil {
		return fmt.Errorf("store returned nil handle for existing keyset '%s'", keysetName)
	}
	if currentMetadata == nil {
		return fmt.Errorf("store returned nil metadata for existing keyset '%s'", keysetName)
	}
	// A valid policy is required for rotation
	if currentMetadata.RotationPolicy == nil {
		log.Printf("AutoRotator: Skipping keyset '%s' because metadata lacks a RotationPolicy.", keysetName)
		return ErrRotationPolicyMissing // Return specific error
	}
	// Validate the policy structure itself (durations, template presence)
	if err := ValidateRotationPolicy(currentMetadata.RotationPolicy); err != nil {
		log.Printf("AutoRotator: Skipping keyset '%s' due to invalid RotationPolicy: %v", keysetName, err)
		return fmt.Errorf("invalid rotation policy for keyset '%s': %w", keysetName, err)
	}

	// Clone the original metadata *before* passing it to the rotator function
	originalMetadataClone := proto.Clone(currentMetadata)
	// Clone the original keyset info for comparison
	originalKeysetInfoClone := proto.Clone(currentHandle.KeysetInfo())

	log.Printf("AutoRotator: Read keyset '%s' version %v from store. Processing rotation...", keysetName, currentContext)

	// --- Perform Rotation Logic using the standalone function ---
	// Use the AutoRotator's time source
	currentTime := ar.now()
	newHandle, newMetadata, rotationErr := RotateKeyset(currentTime, currentHandle, currentMetadata)

	if rotationErr != nil {
		// Log the error but return it, allowing RunOnce to continue with other keysets
		log.Printf("AutoRotator: Rotation logic failed for keyset '%s': %v", keysetName, rotationErr)
		return fmt.Errorf("rotation logic failed for keyset '%s': %w", keysetName, rotationErr)
	}

	// --- Check if Changes Occurred ---
	// Note: RotateKeyset now returns the *original* handle/metadata if no error occurred AND no changes were needed.
	// We still need to compare the returned objects with the originals.
	metadataChanged := !proto.Equal(originalMetadataClone, newMetadata)
	keysetChanged := !proto.Equal(originalKeysetInfoClone, newHandle.KeysetInfo())

	// --- Write Back to Store (Only If Changed) ---
	if !metadataChanged && !keysetChanged {
		log.Printf("AutoRotator: No changes detected for keyset '%s', skipping write.", keysetName)
		return nil
	}

	log.Printf("AutoRotator: Changes detected for keyset '%s' (MetadataChanged: %t, KeysetChanged: %t). Attempting to write updated state (expected context: %v)...",
		keysetName, metadataChanged, keysetChanged, currentContext)

	writeErr := ar.store.WriteKeysetAndMetadata(ctx, keysetName, newHandle, newMetadata, currentContext)

	if writeErr != nil {
		if errors.Is(writeErr, ErrOptimisticLockFailed) {
			log.Printf("AutoRotator: Optimistic lock failed during write for keyset '%s', another process may have updated concurrently. Will retry on next cycle.", keysetName)
			// Treat lock failure as non-fatal for this specific keyset, let next cycle retry
			return nil
		}
		// Other write errors are fatal for this keyset cycle
		return fmt.Errorf("failed to write updated state to store for keyset '%s': %w", keysetName, writeErr)
	}

	log.Printf("AutoRotator: Successfully updated state for keyset '%s' in store.", keysetName)
	return nil
}

// Start begins the background rotation routine.
// It periodically calls RunOnce to process all existing keysets.
func (ar *AutoRotator) Start(ctx context.Context) {
	ar.mu.Lock()
	if ar.running {
		ar.mu.Unlock()
		log.Println("AutoRotator: Background routine already running.")
		return
	}

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
			log.Printf("AutoRotator: Error during initial run cycle: %v", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := ar.RunOnce(runCtx); err != nil {
					log.Printf("AutoRotator: Error during periodic run cycle: %v", err)
				}
			case <-ar.stopChan:
				log.Println("AutoRotator: Received stop signal, background routine shutting down.")
				return
			case <-runCtx.Done():
				log.Println("AutoRotator: Context cancelled, background routine shutting down.")
				return
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
	close(ar.stopChan)

	if ar.cancelCtx != nil {
		ar.cancelCtx()
	}
	ar.mu.Unlock() // Unlock before waiting

	log.Println("AutoRotator: Waiting for background routine to shut down...")
	ar.shutdownWg.Wait()
	ar.mu.Lock() // Re-acquire lock to safely update running status
	ar.running = false
	ar.cancelCtx = nil
	ar.mu.Unlock()
	log.Println("AutoRotator: Background routine shut down successfully.")
}

// ProvisionKeyset explicitly provisions a new keyset with the given name and rotation policy.
// The provided policy (including key template and durations) will be embedded in the
// keyset's metadata.
// It returns ErrKeysetExists if a keyset with that name already exists.
// It returns an error if the policy is invalid or if there are errors during key
// generation or writing to the store.
func (ar *AutoRotator) ProvisionKeyset(ctx context.Context, keysetName string, policy *tinkrotatev1.RotationPolicy) error {
	log.Printf("AutoRotator: Attempting explicit provisioning for keyset '%s'...", keysetName)

	// 1. Validate the provided policy first
	if err := ValidateRotationPolicy(policy); err != nil {
		log.Printf("AutoRotator: Provisioning failed for keyset '%s': Invalid policy provided: %v", keysetName, err)
		return fmt.Errorf("invalid rotation policy provided for provisioning: %w", err)
	}

	// 2. Check if keyset already exists
	readResult, err := ar.store.ReadKeysetAndMetadata(ctx, keysetName)
	if err == nil && readResult != nil {
		// Keyset found, return specific error
		log.Printf("AutoRotator: Provisioning failed for keyset '%s': %v", keysetName, ErrKeysetExists)
		return ErrKeysetExists
	}
	if !errors.Is(err, ErrKeysetNotFound) {
		// An unexpected error occurred during the read check
		log.Printf("AutoRotator: Error checking existence for keyset '%s': %v", keysetName, err)
		return fmt.Errorf("failed to check store for keyset '%s': %w", keysetName, err)
	}
	// err is ErrKeysetNotFound, proceed

	// 3. Get key template from the provided policy
	keyTemplate := policy.KeyTemplate // Already validated policy ensures this isn't nil

	// 4. Generate initial keyset handle
	manager := keyset.NewManager()
	keyID, err := manager.Add(keyTemplate)
	if err != nil {
		err = fmt.Errorf("failed to add initial key using template for keyset '%s': %w", keysetName, err)
		log.Printf("AutoRotator: Provisioning failed for keyset '%s': %v", keysetName, err)
		return err
	}
	err = manager.SetPrimary(keyID)
	if err != nil {
		err = fmt.Errorf("failed to set initial primary key for keyset '%s': %w", keysetName, err)
		log.Printf("AutoRotator: Provisioning failed for keyset '%s': %v", keysetName, err)
		return err
	}
	handle, err := manager.Handle()
	if err != nil {
		err = fmt.Errorf("failed to get initial handle for keyset '%s': %w", keysetName, err)
		log.Printf("AutoRotator: Provisioning failed for keyset '%s': %v", keysetName, err)
		return err
	}

	// 5. Create initial metadata, embedding the *provided policy*
	now := ar.now()
	metadata := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: policy, // Embed the provided policy
		KeyMetadata: map[uint32]*tinkrotatev1.KeyMetadata{
			keyID: {
				KeyId:         keyID,
				State:         tinkrotatev1.KeyState_KEY_STATE_PRIMARY,
				CreationTime:  timestamppb.New(now),
				PromotionTime: timestamppb.New(now), // Primary on creation
			},
		},
	}

	// 6. Write to store (expecting nil context for initial write)
	log.Printf("AutoRotator: Writing newly provisioned keyset '%s' (key ID %d) to store...", keysetName, keyID)
	writeErr := ar.store.WriteKeysetAndMetadata(ctx, keysetName, handle, metadata, nil)
	if writeErr != nil {
		log.Printf("AutoRotator: Failed to write provisioned keyset '%s' to store: %v", keysetName, writeErr)
		// Potentially check for specific store errors like "already exists" if the initial read raced.
		return fmt.Errorf("failed to write initial state to store for keyset '%s': %w", keysetName, writeErr)
	}

	log.Printf("AutoRotator: Successfully provisioned keyset '%s' in store.", keysetName)
	return nil
}

// Helper function to create a default rotation policy for convenience
// (e.g., for tests or simple provisioning)
// NOTE: Users should carefully choose their templates and durations.
func CreateDefaultPolicy(template *tinkpb.KeyTemplate) *tinkrotatev1.RotationPolicy {
	return &tinkrotatev1.RotationPolicy{
		KeyTemplate:         template,
		PrimaryDuration:     durationpb.New(7 * 24 * time.Hour),  // 7 days
		PropagationTime:     durationpb.New(1 * time.Hour),       // 1 hour
		PhaseOutDuration:    durationpb.New(7 * 24 * time.Hour),  // 7 days
		DeletionGracePeriod: durationpb.New(30 * 24 * time.Hour), // 30 days
	}
}
