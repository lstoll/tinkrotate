package tinkrotate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrKeysetExists = errors.New("keyset already exists")
var ErrRotationPolicyMissing = errors.New("rotation policy missing in metadata")

type AutoRotatorOpts struct {
	// ProvisionPolicies specifies a map of keyset names to their desired rotation
	// policies. If a keyset name listed here does not exist in the store when
	// RunOnce executes, the AutoRotator will attempt to provision it using the
	// provided policy.
	ProvisionPolicies map[string]*tinkrotatev1.RotationPolicy
	Logger            *slog.Logger
	TimeSource        func() time.Time
}

// AutoRotator manages the lifecycle of Tink keysets within a store, performing
// automatic rotation based on a schedule and the policies defined within each keyset's metadata.
type AutoRotator struct {
	store             ManagedStore
	checkInterval     time.Duration
	now               func() time.Time
	provisionPolicies map[string]*tinkrotatev1.RotationPolicy
	logger            *slog.Logger

	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
	shutdownWg sync.WaitGroup
	cancelCtx  context.CancelFunc
}

func NewAutoRotator(store ManagedStore, checkInterval time.Duration, opts *AutoRotatorOpts) (*AutoRotator, error) {
	if store == nil {
		return nil, errors.New("store cannot be nil")
	}
	if checkInterval <= 0 {
		return nil, errors.New("checkInterval must be positive")
	}

	provisionPolicies := make(map[string]*tinkrotatev1.RotationPolicy)
	var logger *slog.Logger
	if opts != nil {
		if opts.Logger != nil {
			logger = opts.Logger
		}
		if opts.ProvisionPolicies != nil {
			for name, policy := range opts.ProvisionPolicies {
				if err := ValidateRotationPolicy(policy); err != nil {
					return nil, fmt.Errorf("invalid policy provided in ProvisionPolicies for keyset '%s': %w", name, err)
				}
				provisionPolicies[name] = policy
			}
		}
	}

	if logger == nil {
		logger = slog.Default().With("component", "autorotator")
	}

	ar := &AutoRotator{
		store:             store,
		checkInterval:     checkInterval,
		now:               time.Now,
		provisionPolicies: provisionPolicies,
		running:           false,
		logger:            logger,
	}

	if opts != nil && opts.TimeSource != nil {
		ar.now = opts.TimeSource
	}

	return ar, nil
}

// RunOnce performs a single check-and-rotate cycle for all keysets found in the store.
func (ar *AutoRotator) RunOnce(ctx context.Context) error {
	ar.logger.Info("Starting rotation check cycle")
	var firstError error
	processedKeys := make(map[string]struct{})

	err := ar.store.ForEachKeyset(ctx, func(keysetName string) error {
		processedKeys[keysetName] = struct{}{}
		runErr := ar.processSingleKeyset(ctx, keysetName)
		if runErr != nil {
			ar.logger.Error("Error processing keyset", "keyset_name", keysetName, "error", runErr)
			if firstError == nil {
				firstError = fmt.Errorf("error processing keyset '%s': %w", keysetName, runErr)
			}
		}
		return nil
	})

	if err != nil {
		errorMsg := "Failed iterating keysets in store"
		if firstError == nil {
			firstError = fmt.Errorf("%s: %w", errorMsg, err)
			ar.logger.Error(errorMsg, "error", err)
		} else {
			ar.logger.Error(errorMsg, "error", err, "prior_error", firstError)
		}
	}

	if len(ar.provisionPolicies) > 0 {
		for keysetName, policy := range ar.provisionPolicies {
			if _, alreadyProcessed := processedKeys[keysetName]; alreadyProcessed {
				continue
			}

			// Check if it exists now. We expect ErrKeysetNotFound if we need to provision.
			_, readErr := ar.store.ReadKeysetAndMetadata(ctx, keysetName)

			if readErr == nil {
				ar.logger.Warn("Specified keyset found unexpectedly, skipping provisioning", "keyset_name", keysetName)
				continue
			}

			if errors.Is(readErr, ErrKeysetNotFound) {
				ar.logger.Info("Attempting to provision specified keyset", "keyset_name", keysetName)
				provisionErr := ar.ProvisionKeyset(ctx, keysetName, policy)
				if provisionErr != nil {
					ar.logger.Error("Failed to provision specified keyset", "keyset_name", keysetName, "error", provisionErr)
					if firstError == nil {
						firstError = fmt.Errorf("failed to provision specified keyset '%s': %w", keysetName, provisionErr)
					}
				} else {
					ar.logger.Info("Successfully provisioned specified keyset", "keyset_name", keysetName)
				}
			} else {
				ar.logger.Error("Error checking existence of specified keyset for provisioning", "keyset_name", keysetName, "error", readErr)
				if firstError == nil {
					firstError = fmt.Errorf("error checking existence of specified keyset '%s': %w", keysetName, readErr)
				}
			}
		}
	}

	ar.logger.Info("Finished rotation check cycle")
	return firstError
}

func (ar *AutoRotator) processSingleKeyset(ctx context.Context, keysetName string) error {
	readResult, err := ar.store.ReadKeysetAndMetadata(ctx, keysetName)

	if err != nil {
		if errors.Is(err, ErrKeysetNotFound) {
			ar.logger.Warn("Keyset not found during processing (skipped)", "keyset_name", keysetName)
			return nil
		}
		return fmt.Errorf("failed to read from store for keyset '%s': %w", keysetName, err)
	}

	currentHandle := readResult.Handle
	currentMetadata := readResult.Metadata
	currentContext := readResult.Context

	if currentHandle == nil {
		return fmt.Errorf("store returned nil handle for existing keyset '%s'", keysetName)
	}
	if currentMetadata == nil {
		return fmt.Errorf("store returned nil metadata for existing keyset '%s'", keysetName)
	}
	if currentMetadata.RotationPolicy == nil {
		ar.logger.Warn("Skipping keyset because metadata lacks a RotationPolicy", "keyset_name", keysetName)
		return ErrRotationPolicyMissing
	}
	if err := ValidateRotationPolicy(currentMetadata.RotationPolicy); err != nil {
		ar.logger.Error("Skipping keyset due to invalid RotationPolicy", "keyset_name", keysetName, "error", err)
		return fmt.Errorf("invalid rotation policy for keyset '%s': %w", keysetName, err)
	}

	originalMetadataClone := proto.Clone(currentMetadata)
	originalKeysetInfoClone := proto.Clone(currentHandle.KeysetInfo())

	newHandle, newMetadata, rotated, rotationErr := RotateKeyset(currentHandle, currentMetadata, &RotateOpts{
		TimeSource: func() time.Time {
			return ar.now()
		},
		Logger: ar.logger.With("keyset_name", keysetName),
	})

	if rotationErr != nil {
		ar.logger.Error("Rotation logic failed for keyset", "keyset_name", keysetName, "error", rotationErr)
		return fmt.Errorf("rotation logic failed for keyset '%s': %w", keysetName, rotationErr)
	}

	// Note: RotateKeyset now returns the *original* handle/metadata if no error occurred AND no changes were needed.
	// We still need to compare the returned objects with the originals.
	metadataChanged := !proto.Equal(originalMetadataClone, newMetadata)
	keysetChanged := !proto.Equal(originalKeysetInfoClone, newHandle.KeysetInfo())

	if !rotated {
		if metadataChanged || keysetChanged {
			ar.logger.Warn("RotateKeyset reported no rotation, but proto.Equal detected changes. This indicates a discrepancy.", "keyset_name", keysetName, "metadata_changed_by_equal", metadataChanged, "keyset_changed_by_equal", keysetChanged)
		} else {
			return nil
		}
	}

	ar.logger.Info("Changes indicated by RotateKeyset, attempting write", "keyset_name", keysetName, "metadata_changed_by_equal", metadataChanged, "keyset_changed_by_equal", keysetChanged, "context", currentContext)

	writeErr := ar.store.WriteKeysetAndMetadata(ctx, keysetName, newHandle, newMetadata, currentContext)

	if writeErr != nil {
		if errors.Is(writeErr, ErrOptimisticLockFailed) {
			ar.logger.Warn("Optimistic lock failed during write, another process may have updated concurrently", "keyset_name", keysetName)
			return nil
		}
		ar.logger.Error("Failed to write updated state to store", "keyset_name", keysetName, "error", writeErr)
		return fmt.Errorf("failed to write updated state to store for keyset '%s': %w", keysetName, writeErr)
	}

	ar.logger.Info("Successfully updated state in store", "keyset_name", keysetName)
	return nil
}

// Start begins the background rotation routine.
func (ar *AutoRotator) Start(ctx context.Context) {
	ar.mu.Lock()
	if ar.running {
		ar.mu.Unlock()
		ar.logger.Info("Background routine already running")
		return
	}

	runCtx, cancel := context.WithCancel(ctx)
	ar.cancelCtx = cancel

	ar.running = true
	ar.stopChan = make(chan struct{})
	ar.shutdownWg.Add(1)
	ar.mu.Unlock()

	ar.logger.Info("Starting background rotation routine")

	go func() {
		defer ar.shutdownWg.Done()
		ticker := time.NewTicker(ar.checkInterval)
		defer ticker.Stop()

		ar.logger.Info("Background routine started")

		// Run once immediately on start
		if err := ar.RunOnce(runCtx); err != nil {
			ar.logger.Error("Error during initial run cycle", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := ar.RunOnce(runCtx); err != nil {
					ar.logger.Error("Error during periodic run cycle", "error", err)
				}
			case <-ar.stopChan:
				ar.logger.Info("Received stop signal, background routine shutting down")
				return
			case <-runCtx.Done():
				ar.logger.Warn("Context cancelled, background routine shutting down", "error", runCtx.Err())
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
		ar.logger.Info("Stop called but background routine was not running")
		return
	}

	ar.logger.Info("Signaling background routine to stop")
	close(ar.stopChan)

	if ar.cancelCtx != nil {
		ar.cancelCtx()
	}
	ar.mu.Unlock()

	ar.logger.Info("Waiting for background routine to shut down")
	ar.shutdownWg.Wait()
	ar.mu.Lock()
	ar.running = false
	ar.cancelCtx = nil
	ar.mu.Unlock()
	ar.logger.Info("Background routine shut down successfully")
}

// ProvisionKeyset explicitly provisions a new keyset with the given name and rotation policy.
// It returns ErrKeysetExists if a keyset with that name already exists.
func (ar *AutoRotator) ProvisionKeyset(ctx context.Context, keysetName string, policy *tinkrotatev1.RotationPolicy) error {
	logger := ar.logger.With("keyset_name", keysetName)
	logger.Info("Attempting explicit provisioning")

	if err := ValidateRotationPolicy(policy); err != nil {
		logger.Error("Provisioning failed: Invalid policy provided", "error", err)
		return fmt.Errorf("invalid rotation policy provided for provisioning: %w", err)
	}

	readResult, err := ar.store.ReadKeysetAndMetadata(ctx, keysetName)
	if err == nil && readResult != nil {
		logger.Warn("Provisioning failed: Keyset already exists", "error", ErrKeysetExists)
		return ErrKeysetExists
	}
	if !errors.Is(err, ErrKeysetNotFound) {
		logger.Error("Provisioning failed: Error checking existence", "error", err)
		return fmt.Errorf("failed to check store for keyset '%s': %w", keysetName, err)
	}

	keyTemplate := policy.KeyTemplate

	manager := keyset.NewManager()
	keyID, err := manager.Add(keyTemplate)
	if err != nil {
		err = fmt.Errorf("failed to add initial key using template for keyset '%s': %w", keysetName, err)
		logger.Error("Provisioning failed: Failed to add initial key", "error", err)
		return err
	}
	logger = logger.With("initial_key_id", keyID)
	err = manager.SetPrimary(keyID)
	if err != nil {
		err = fmt.Errorf("failed to set initial primary key for keyset '%s': %w", keysetName, err)
		logger.Error("Provisioning failed: Failed to set initial primary key", "error", err)
		return err
	}
	handle, err := manager.Handle()
	if err != nil {
		err = fmt.Errorf("failed to get initial handle for keyset '%s': %w", keysetName, err)
		logger.Error("Provisioning failed: Failed to get initial handle", "error", err)
		return err
	}

	now := ar.now()
	metadata := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: policy,
		KeyMetadata: map[uint32]*tinkrotatev1.KeyMetadata{
			keyID: {
				KeyId:         keyID,
				State:         tinkrotatev1.KeyState_KEY_STATE_PRIMARY,
				CreationTime:  timestamppb.New(now),
				PromotionTime: timestamppb.New(now),
			},
		},
	}

	handle, metadata, _, err = RotateKeyset(handle, metadata, &RotateOpts{
		TimeSource: ar.now,
		Logger:     ar.logger,
	})
	if err != nil {
		logger.Error("Failed to rotate provisioned keyset", "error", err)
		return fmt.Errorf("failed to rotate provisioned keyset: %w", err)
	}

	logger.Info("Writing newly provisioned keyset to store")
	writeErr := ar.store.WriteKeysetAndMetadata(ctx, keysetName, handle, metadata, nil)
	if writeErr != nil {
		logger.Error("Failed to write provisioned keyset to store", "error", writeErr)
		return fmt.Errorf("failed to write initial state to store for keyset '%s': %w", keysetName, writeErr)
	}

	logger.Info("Successfully provisioned keyset in store")
	return nil
}

// CreateDefaultPolicy creates a default rotation policy for convenience.
// Users should carefully choose their templates and durations.
func CreateDefaultPolicy(template *tinkpb.KeyTemplate) *tinkrotatev1.RotationPolicy {
	return &tinkrotatev1.RotationPolicy{
		KeyTemplate:         template,
		PrimaryDuration:     durationpb.New(7 * 24 * time.Hour),  // 7 days
		PropagationTime:     durationpb.New(1 * time.Hour),       // 1 hour
		PhaseOutDuration:    durationpb.New(7 * 24 * time.Hour),  // 7 days
		DeletionGracePeriod: durationpb.New(30 * 24 * time.Hour), // 30 days
	}
}