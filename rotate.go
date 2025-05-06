package tinkrotate

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ValidateRotationPolicy checks if the provided policy has valid durations.
func ValidateRotationPolicy(policy *tinkrotatev1.RotationPolicy) error {
	if policy == nil {
		return errors.New("rotation policy cannot be nil")
	}
	if policy.KeyTemplate == nil {
		return errors.New("key template must be provided in rotation policy")
	}
	pDur := policy.PrimaryDuration.AsDuration()
	propTime := policy.PropagationTime.AsDuration()
	phaseDur := policy.PhaseOutDuration.AsDuration()
	delGrace := policy.DeletionGracePeriod.AsDuration()

	if pDur <= 0 {
		return errors.New("primary duration must be positive")
	}
	if propTime < 0 || phaseDur < 0 || delGrace < 0 {
		return errors.New("propagation, phase-out, and deletion grace periods cannot be negative")
	}
	if propTime > pDur {
		// Allow propagation == primary duration (immediate rotation after propagation)
		return errors.New("propagation time cannot be longer than primary duration")
	}
	return nil
}

type RotateOpts struct {
	TimeSource func() time.Time
	Logger     *slog.Logger
}

// RotateKeyset performs one rotation cycle based on the provided current time.
// It reads the rotation policy *from the metadata* itself.
// It takes the current keyset handle and its corresponding metadata,
// applies the rotation policy, and returns the potentially modified
// keyset handle and updated metadata.
// The caller is responsible for persisting the returned handle and metadata.
func RotateKeyset(
	handle *keyset.Handle,
	metadata *tinkrotatev1.KeyRotationMetadata,
	opts *RotateOpts,
) (*keyset.Handle, *tinkrotatev1.KeyRotationMetadata, error) {

	// --- Setup Logger ---
	var logger *slog.Logger
	if opts != nil && opts.Logger != nil {
		logger = opts.Logger
	} else {
		logger = slog.New(slog.DiscardHandler)
	}
	logger = logger.With("function", "RotateKeyset")

	// --- Validate Inputs ---
	if handle == nil {
		return nil, nil, errors.New("keyset handle cannot be nil")
	}
	if metadata == nil {
		// If handle is not empty, require metadata
		if len(handle.KeysetInfo().GetKeyInfo()) > 0 {
			return nil, nil, errors.New("metadata cannot be nil for non-empty keyset")
		}
		// Allow nil metadata only if handle is also effectively empty/new
		metadata = &tinkrotatev1.KeyRotationMetadata{}
	}
	// Ensure key metadata map exists even if policy is missing initially
	if metadata.KeyMetadata == nil {
		metadata.KeyMetadata = make(map[uint32]*tinkrotatev1.KeyMetadata)
	}
	// Get and validate the policy *from the metadata*
	policy := metadata.RotationPolicy
	if err := ValidateRotationPolicy(policy); err != nil {
		return nil, nil, fmt.Errorf("invalid rotation policy in metadata: %w", err)
	}

	currentTime := time.Now()
	if opts != nil && opts.TimeSource != nil {
		currentTime = opts.TimeSource()
	}

	// --- Policy Durations (extracted for readability) ---
	primaryDuration := policy.PrimaryDuration.AsDuration()
	propagationTime := policy.PropagationTime.AsDuration()
	phaseOutDuration := policy.PhaseOutDuration.AsDuration()
	deletionGracePeriod := policy.DeletionGracePeriod.AsDuration()
	keyTemplate := policy.KeyTemplate

	// --- Consistency Check ---
	inconsistencies := CheckConsistency(handle, metadata)
	if len(inconsistencies) > 0 {
		// Allow processing even with inconsistencies? For now, return error.
		return nil, nil, fmt.Errorf("inconsistencies found before rotation: %v", inconsistencies)
	}

	manager := keyset.NewManagerFromHandle(handle)
	ksInfo := handle.KeysetInfo()
	updated := false // Track if any changes were made

	// --- Build current state view ---
	keyInfos := make(map[uint32]*KeyInfo) // Map key ID to combined info
	var primaryKey *KeyInfo
	var pendingKeys []*KeyInfo
	var phasingOutKeys []*KeyInfo
	var disabledKeys []*KeyInfo

	// Collect current keys and their metadata states
	for _, keyInfo := range ksInfo.GetKeyInfo() {
		keyID := keyInfo.GetKeyId()
		meta, metaExists := metadata.KeyMetadata[keyID]

		if !metaExists {
			logger.Warn("Key ID found in keyset but not in metadata. Skipping.", "keyID", keyID)
			continue
		}

		currentState := meta.State
		currentStatus := keyInfo.GetStatus()
		if currentState == tinkrotatev1.KeyState_KEY_STATE_PRIMARY && currentStatus != tinkpb.KeyStatusType_ENABLED && keyInfo.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW { // Primary must be enabled (unless RAW key) - Tink enforces this via SetPrimary
			logger.Warn("Key metadata state is PRIMARY, but Tink status is different.", "keyID", keyID, "tink_status", currentStatus)
		}
		if (currentState == tinkrotatev1.KeyState_KEY_STATE_PENDING || currentState == tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT) && currentStatus != tinkpb.KeyStatusType_ENABLED {
			logger.Warn("Key metadata state requires ENABLED Tink status, but found different.", "keyID", keyID, "metadata_state", currentState, "tink_status", currentStatus)
		}
		if currentState == tinkrotatev1.KeyState_KEY_STATE_DISABLED && currentStatus != tinkpb.KeyStatusType_DISABLED {
			logger.Warn("Key metadata state is DISABLED, but Tink status is different.", "keyID", keyID, "tink_status", currentStatus)
		}

		ki := &KeyInfo{
			KeyID:    keyID,
			Status:   keyInfo.GetStatus(),
			Metadata: meta,
		}
		keyInfos[keyID] = ki

		switch meta.State {
		case tinkrotatev1.KeyState_KEY_STATE_PRIMARY:
			if primaryKey != nil {
				logger.Warn("Multiple keys marked as PRIMARY in metadata. Using first encountered.", "existing_primary_key_id", primaryKey.KeyID, "new_primary_key_id", ki.KeyID, "using_key_id", primaryKey.KeyID)
			} else {
				primaryKey = ki
			}
		case tinkrotatev1.KeyState_KEY_STATE_PENDING:
			pendingKeys = append(pendingKeys, ki)
		case tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT:
			phasingOutKeys = append(phasingOutKeys, ki)
		case tinkrotatev1.KeyState_KEY_STATE_DISABLED:
			disabledKeys = append(disabledKeys, ki)
		}
	}

	sort.Slice(pendingKeys, func(i, j int) bool {
		t1 := time.Time{}
		if pendingKeys[i].Metadata.CreationTime != nil {
			t1 = pendingKeys[i].Metadata.CreationTime.AsTime()
		}
		t2 := time.Time{}
		if pendingKeys[j].Metadata.CreationTime != nil {
			t2 = pendingKeys[j].Metadata.CreationTime.AsTime()
		}
		return t1.Before(t2)
	})

	// --- 1. Process Deletions ---
	keysToDelete := []uint32{}
	for _, ki := range disabledKeys {
		if ki.Metadata == nil || ki.Metadata.DeletionTime == nil {
			logger.Warn("Disabled key missing metadata or deletion time. Skipping deletion check.", "keyID", ki.KeyID)
			continue
		}

		if !currentTime.Before(ki.Metadata.DeletionTime.AsTime()) {
			tinkKeyInfo, err := findTinkKeyInfo(manager, ki.KeyID)
			if err != nil {
				logger.Warn("Could not find Tink info for key during deletion check. Skipping.", "keyID", ki.KeyID, "error", err)
				continue
			}

			if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_DESTROYED {
				logger.Info("Deleting key (past deletion time).", "keyID", ki.KeyID, "deletion_time", ki.Metadata.DeletionTime.AsTime().Format(time.RFC3339))
				err := manager.Delete(ki.KeyID)
				if err != nil {
					logger.Error("Failed to delete key.", "keyID", ki.KeyID, "error", err)
				} else {
					keysToDelete = append(keysToDelete, ki.KeyID) // Mark for metadata removal
					updated = true
				}
			} else {
				if _, exists := metadata.KeyMetadata[ki.KeyID]; exists {
					keysToDelete = append(keysToDelete, ki.KeyID)
					updated = true // Metadata changed
				}
			}
		}
	}
	for _, keyID := range keysToDelete {
		delete(metadata.KeyMetadata, keyID)
	}

	// --- 2. Process Disabling (Phasing-Out -> Disabled) ---
	for _, ki := range phasingOutKeys {
		if ki.Metadata == nil {
			logger.Warn("Phasing-out key missing metadata. Skipping disable check.", "keyID", ki.KeyID)
			continue
		}

		disableTimeKnown := false
		var expectedDisableTime time.Time
		if primaryKey != nil && primaryKey.Metadata != nil && primaryKey.Metadata.PromotionTime != nil {
			expectedDisableTime = primaryKey.Metadata.PromotionTime.AsTime().Add(phaseOutDuration)
			disableTimeKnown = true
		} else {
			// Fallback: Use phasing-out key's own creation + primary duration + phase-out duration.
			if ki.Metadata.CreationTime != nil {
				expectedDisableTime = ki.Metadata.CreationTime.AsTime().Add(primaryDuration).Add(phaseOutDuration)
				disableTimeKnown = true
				logger.Info("Key using fallback disable time check.", "keyID", ki.KeyID)
			} else {
				logger.Warn("Phasing-out key missing creation time. Cannot determine disable time. Skipping.", "keyID", ki.KeyID)
			}
		}

		if disableTimeKnown && !currentTime.Before(expectedDisableTime) {
			tinkKeyInfo, err := findTinkKeyInfo(manager, ki.KeyID)
			if err != nil {
				logger.Warn("Could not find Tink info for key during disable check. Skipping.", "keyID", ki.KeyID, "error", err)
				continue
			}

			if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_ENABLED {
				logger.Info("Disabling key (phase-out period ended).", "keyID", ki.KeyID, "expected_disable_time", expectedDisableTime.Format(time.RFC3339))
				err := manager.Disable(ki.KeyID)
				if err != nil {
					logger.Error("Failed to disable key.", "keyID", ki.KeyID, "error", err)
					continue // Skip metadata update on error
				}
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				ki.Metadata.DisableTime = timestamppb.New(currentTime)
				ki.Metadata.DeletionTime = timestamppb.New(currentTime.Add(deletionGracePeriod))
				updated = true
			} else if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_DISABLED && ki.Metadata.State != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				logger.Info("Aligning metadata for already disabled key.", "keyID", ki.KeyID)
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				if ki.Metadata.DisableTime == nil {
					ki.Metadata.DisableTime = timestamppb.New(currentTime)
				}
				if ki.Metadata.DisableTime != nil && ki.Metadata.DeletionTime == nil {
					ki.Metadata.DeletionTime = timestamppb.New(ki.Metadata.DisableTime.AsTime().Add(deletionGracePeriod))
				} else if ki.Metadata.DeletionTime == nil {
					ki.Metadata.DeletionTime = timestamppb.New(currentTime.Add(deletionGracePeriod))
				}
				updated = true
			}
		}
	}

	// --- 3. Process Promotion (Pending -> Primary) ---
	if primaryKey != nil {
		if primaryKey.Metadata == nil {
			logger.Warn("Primary key missing metadata. Skipping promotion check.", "keyID", primaryKey.KeyID)
		} else {
			primaryExpired := false
			expiryTimeKnown := false
			var expectedEndTime time.Time
			if primaryKey.Metadata.PromotionTime != nil {
				expectedEndTime = primaryKey.Metadata.PromotionTime.AsTime().Add(primaryDuration)
				expiryTimeKnown = true
			} else if primaryKey.Metadata.CreationTime != nil {
				expectedEndTime = primaryKey.Metadata.CreationTime.AsTime().Add(primaryDuration)
				expiryTimeKnown = true
				logger.Warn("Primary key missing promotion time. Using creation time for expiry check.", "keyID", primaryKey.KeyID)
			} else {
				logger.Warn("Primary key missing both promotion and creation time. Cannot check expiry.", "keyID", primaryKey.KeyID)
			}

			if expiryTimeKnown && !currentTime.Before(expectedEndTime) {
				primaryExpired = true
			}

			if primaryExpired {
				if len(pendingKeys) > 0 {
					promoted := false
					for _, pendingKey := range pendingKeys {
						if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
							logger.Warn("Pending key missing metadata or creation time. Skipping promotion check for this key.", "keyID", pendingKey.KeyID)
							continue
						}

						tinkKeyInfo, err := findTinkKeyInfo(manager, pendingKey.KeyID)
						if err != nil {
							logger.Warn("Could not find Tink info for pending key during promotion check. Skipping.", "keyID", pendingKey.KeyID, "error", err)
							continue
						}
						if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
							logger.Warn("Pending key is not ENABLED in keyset. Skipping promotion.", "keyID", pendingKey.KeyID, "tink_status", tinkKeyInfo.GetStatus())
							continue
						}

						propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(propagationTime)
						if !currentTime.Before(propagationEndTime) {
							logger.Info("Promoting key to PRIMARY (Primary expired, propagation time met).", "pending_key_id", pendingKey.KeyID, "primary_key_id", primaryKey.KeyID, "primary_expiry_time", expectedEndTime.Format(time.RFC3339))
							err := manager.SetPrimary(pendingKey.KeyID)
							if err != nil {
								logger.Error("Failed to promote key.", "keyID", pendingKey.KeyID, "error", err)
								continue
							}

							primaryKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT

							pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
							pendingKey.Metadata.PromotionTime = timestamppb.New(currentTime)

							updated = true
							promoted = true
							break // Promotion successful
						} else {
							logger.Info("Primary key expired, but pending key hasn't met propagation time. Waiting.",
								"primary_key_id", primaryKey.KeyID, "pending_key_id", pendingKey.KeyID, "propagation_time_remaining", propagationEndTime.Sub(currentTime).Round(time.Second), "propagation_end_time", propagationEndTime.Format(time.RFC3339))
							break // Block promotion, wait for next cycle
						}
					}
					if !promoted && len(pendingKeys) > 0 {
						logger.Info("Primary key expired, but no suitable pending key ready for promotion yet.", "primary_key_id", primaryKey.KeyID)
					} else if len(pendingKeys) == 0 {
						logger.Warn("Primary key expired, but NO PENDING key available to promote.", "keyID", primaryKey.KeyID)
					}
				} else {
					logger.Warn("Primary key expired, but NO PENDING key available to promote.", "keyID", primaryKey.KeyID)
				}
			}
		}
	} else { // No primary key exists
		if len(pendingKeys) > 0 {
			pendingKey := pendingKeys[0] // Oldest one
			if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
				logger.Warn("Pending key missing metadata or creation time. Cannot promote.", "keyID", pendingKey.KeyID)
			} else {
				tinkKeyInfo, err := findTinkKeyInfo(manager, pendingKey.KeyID)
				if err != nil {
					logger.Warn("Could not find Tink info for pending key during initial promotion check. Skipping.", "keyID", pendingKey.KeyID, "error", err)
				} else if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
					logger.Warn("Pending key is not ENABLED. Cannot promote.", "keyID", pendingKey.KeyID, "tink_status", tinkKeyInfo.GetStatus())
				} else {
					propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(propagationTime)
					if !currentTime.Before(propagationEndTime) {
						logger.Info("Promoting key to PRIMARY (no primary exists, propagation time met).", "keyID", pendingKey.KeyID)
						err := manager.SetPrimary(pendingKey.KeyID)
						if err != nil {
							logger.Error("Failed to promote key.", "keyID", pendingKey.KeyID, "error", err)
						} else {
							pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
							pendingKey.Metadata.PromotionTime = timestamppb.New(currentTime)
							updated = true
						}
					} else {
						logger.Info("No primary key, pending key not ready for promotion.",
							"pending_key_id", pendingKey.KeyID, "propagation_time_remaining", propagationEndTime.Sub(currentTime).Round(time.Second), "propagation_end_time", propagationEndTime.Format(time.RFC3339))
					}
				}
			}
		} else {
			logger.Info("No primary key and no pending keys found.")
		}
	}

	// --- Refresh state after potential promotion/generation ---
	// Get potentially updated handle info
	ksInfoHandle, err := manager.Handle()
	if err != nil {
		// If we can't get the handle after potential changes, it's safer to return error
		// and not proceed with generating a new key based on potentially stale info.
		return handle, metadata, fmt.Errorf("failed to get intermediate handle from manager: %w", err)
	}
	ksInfo = ksInfoHandle.KeysetInfo() // Use the latest info
	primaryKey = nil                   // Reset and find again based on latest ksInfo and metadata
	hasPending := false
	// Re-scan metadata and latest KeysetInfo to determine current primary and if pending exists
	for _, keyInfo := range ksInfo.GetKeyInfo() {
		meta, exists := metadata.KeyMetadata[keyInfo.GetKeyId()]
		if !exists {
			continue
		} // Ignore keys without metadata

		currentKeyInfo, kiExists := keyInfos[keyInfo.GetKeyId()]
		if !kiExists {
			// Should not happen if keyInfos was built correctly, but handle defensively
			currentKeyInfo = &KeyInfo{
				KeyID:    keyInfo.GetKeyId(),
				Status:   keyInfo.GetStatus(),
				Metadata: meta,
			}
			keyInfos[keyInfo.GetKeyId()] = currentKeyInfo
		} else {
			currentKeyInfo.Status = keyInfo.GetStatus() // Update status from potentially modified handle
		}

		// Determine primary based on BOTH metadata state AND Tink's view
		if meta.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			if keyInfo.GetKeyId() == ksInfo.GetPrimaryKeyId() {
				if primaryKey != nil {
					// This case was logged earlier, stick with the first one encountered
				} else {
					primaryKey = currentKeyInfo // Found the primary
				}
			} else {
				// Metadata says primary, but Tink disagrees. Correct metadata.
				logger.Warn("Metadata state for key is PRIMARY, but Tink primary is different. Setting state to PHASING_OUT.", "keyID", keyInfo.GetKeyId(), "tink_primary_id", ksInfo.GetPrimaryKeyId())
				meta.State = tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT
				meta.PromotionTime = nil // Clear promotion time
				updated = true
			}
		}
		if meta.State == tinkrotatev1.KeyState_KEY_STATE_PENDING {
			hasPending = true
		}
	}
	// If after checks, primaryKey is still nil, but Tink has a primary ID, fix metadata
	if primaryKey == nil && ksInfo.GetPrimaryKeyId() != 0 {
		tinkPrimaryId := ksInfo.GetPrimaryKeyId()
		meta, exists := metadata.KeyMetadata[tinkPrimaryId]
		if exists {
			if meta.State != tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
				logger.Warn("Tink primary key's metadata state was not PRIMARY. Setting metadata state to PRIMARY.", "tink_primary_id", tinkPrimaryId, "previous_metadata_state", meta.State)
				meta.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
				if meta.PromotionTime == nil { // Set promotion time if missing
					meta.PromotionTime = timestamppb.New(currentTime)
				}
				primaryKey = keyInfos[tinkPrimaryId] // Update local variable
				updated = true
			}
			// If state was already primary, primaryKey should have been set unless keyInfos map was incomplete
		} else {
			logger.Error("Tink primary key has no corresponding metadata!", "tink_primary_id", tinkPrimaryId)
			// This is a critical inconsistency, potentially halt? For now, we logged the error.
		}
	}

	// --- 4. Generate New Pending Key ---
	if primaryKey != nil && !hasPending {
		logger.Info("Generating new PENDING key (Primary exists, no pending key found).", "primary_key_id", primaryKey.KeyID)
		keyID, err := manager.Add(keyTemplate)
		if err != nil {
			// Error adding key, return previous state and error
			return handle, metadata, fmt.Errorf("failed to add new key to manager: %w", err)
		}
		newMeta := &tinkrotatev1.KeyMetadata{
			KeyId:        keyID,
			State:        tinkrotatev1.KeyState_KEY_STATE_PENDING,
			CreationTime: timestamppb.New(currentTime),
		}
		metadata.KeyMetadata[keyID] = newMeta
		updated = true
		logger.Info("Generated new PENDING key.", "keyID", keyID)
	}

	// --- Return updated handle and metadata ---
	var finalHandle *keyset.Handle
	if updated {
		finalHandle, err = manager.Handle()
		if err != nil {
			// Failed to get the *final* handle after all updates.
			return handle, metadata, fmt.Errorf("failed to get final handle from manager: %w", err)
		}
	} else {
		finalHandle = handle // No changes
	}

	// Final consistency check before returning?
	finalInconsistencies := CheckConsistency(finalHandle, metadata)
	if len(finalInconsistencies) > 0 {
		logger.Warn("Inconsistencies found *after* rotation attempt. Returning potentially inconsistent state.", "inconsistencies", finalInconsistencies)
		// Decide: return error, or return the state anyway? Returning state for now.
	}

	return finalHandle, metadata, nil
}

// Helper to find Tink KeyInfo within a manager/handle
func findTinkKeyInfo(m *keyset.Manager, keyID uint32) (*tinkpb.KeysetInfo_KeyInfo, error) {
	h, err := m.Handle() // Get current handle state from manager
	if err != nil {
		return nil, fmt.Errorf("failed to get handle from manager: %w", err)
	}
	for _, ki := range h.KeysetInfo().GetKeyInfo() {
		if ki.GetKeyId() == keyID {
			return ki, nil
		}
	}
	return nil, fmt.Errorf("key ID %d not found in keyset", keyID)
}

// KeyInfo helper struct
type KeyInfo struct {
	KeyID    uint32
	Status   tinkpb.KeyStatusType
	Metadata *tinkrotatev1.KeyMetadata
}

// CheckConsistency verifies state between KeysetHandle and KeyRotationMetadata.
// It needs to handle the new structure of KeyRotationMetadata.
func CheckConsistency(handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata) []error {
	var inconsistencies []error

	// Create a default logger for CheckConsistency, as it doesn't have RotateOpts
	// This could be passed in if CheckConsistency is used in other contexts needing specific logging.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil)).With("function", "CheckConsistency")

	if handle == nil {
		inconsistencies = append(inconsistencies, errors.New("keyset handle is nil"))
		return inconsistencies
	}
	ksInfo := handle.KeysetInfo()

	// --- Validate Metadata Structure ---
	if metadata == nil {
		if len(ksInfo.GetKeyInfo()) > 0 {
			inconsistencies = append(inconsistencies, errors.New("metadata is nil, but keyset handle contains keys"))
		}
		return inconsistencies // Cannot proceed without metadata
	}
	// Rotation policy is now required for rotation, check if it's present.
	// We don't necessarily need to validate its contents here, RotateKeyset does that.
	if metadata.RotationPolicy == nil && len(ksInfo.GetKeyInfo()) > 0 { // Only require policy if keys exist
		inconsistencies = append(inconsistencies, errors.New("metadata.RotationPolicy is nil, but keyset handle contains keys"))
	}
	if metadata.KeyMetadata == nil {
		metadata.KeyMetadata = make(map[uint32]*tinkrotatev1.KeyMetadata) // Treat nil map as empty
		if len(ksInfo.GetKeyInfo()) > 0 {
			inconsistencies = append(inconsistencies, errors.New("metadata.KeyMetadata map is nil/empty, but keyset handle contains keys"))
		}
	}

	// --- 1. Key ID Matching ---
	tinkKeyIDs := make(map[uint32]*tinkpb.KeysetInfo_KeyInfo)
	for _, ki := range ksInfo.GetKeyInfo() {
		if ki == nil {
			continue // Should not happen, but defensive check
		}
		tinkKeyIDs[ki.GetKeyId()] = ki
	}

	metadataKeyIDs := make(map[uint32]*tinkrotatev1.KeyMetadata)
	for kID, meta := range metadata.KeyMetadata {
		if meta == nil {
			inconsistencies = append(inconsistencies, fmt.Errorf("metadata map contains nil entry for key ID %d", kID))
			continue // Skip nil metadata entries
		}
		if meta.KeyId != kID {
			inconsistencies = append(inconsistencies, fmt.Errorf("metadata map key %d does not match metadata message KeyId %d", kID, meta.KeyId))
		}
		metadataKeyIDs[kID] = meta
	}

	// Check if all keys in Tink handle exist in metadata
	for kID := range tinkKeyIDs {
		if _, exists := metadataKeyIDs[kID]; !exists {
			inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d exists in keyset handle but not in metadata", kID))
		}
	}

	// Check if all keys in metadata exist in Tink handle
	for kID := range metadataKeyIDs {
		if _, exists := tinkKeyIDs[kID]; !exists {
			// It's possible the key was DESTROYED, which is valid if metadata state is DISABLED/past deletion time.
			// However, ideally, the metadata entry should be removed upon destruction.
			// Let's flag it as an inconsistency for now.
			inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d exists in metadata but not in keyset handle (was it destroyed without metadata cleanup?)", kID))
		}
	}

	// --- 2. Primary Key Consistency ---
	tinkPrimaryID := ksInfo.GetPrimaryKeyId()
	var metadataPrimaryID uint32
	primaryCount := 0

	for kID, meta := range metadataKeyIDs {
		// Only check keys that actually exist in the handle for primary status consistency
		if _, exists := tinkKeyIDs[kID]; !exists {
			continue
		}
		if meta.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			metadataPrimaryID = kID
			primaryCount++
		}
	}

	if tinkPrimaryID != 0 {
		// Handle has a primary key
		if primaryCount == 0 {
			inconsistencies = append(inconsistencies, fmt.Errorf("keyset handle primary ID is %d, but no key found with state PRIMARY in metadata", tinkPrimaryID))
		} else if primaryCount > 1 {
			inconsistencies = append(inconsistencies, fmt.Errorf("multiple keys (%d found) have state PRIMARY in metadata", primaryCount))
		} else {
			// Exactly one primary found in metadata
			if metadataPrimaryID != tinkPrimaryID {
				inconsistencies = append(inconsistencies, fmt.Errorf("keyset handle primary ID is %d, but metadata PRIMARY key ID is %d", tinkPrimaryID, metadataPrimaryID))
			}
			// Double check the state of the key Tink thinks is primary
			metaForTinkPrimary, exists := metadataKeyIDs[tinkPrimaryID]
			if !exists {
				// This case should be caught by check #1 already, but belt-and-suspenders
				inconsistencies = append(inconsistencies, fmt.Errorf("keyset handle primary ID %d does not exist in metadata", tinkPrimaryID))
			} else if metaForTinkPrimary.State != tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
				inconsistencies = append(inconsistencies, fmt.Errorf("keyset handle primary ID is %d, but its metadata state is %s (expected PRIMARY)", tinkPrimaryID, metaForTinkPrimary.State))
			}
		}
	} else {
		// Handle has NO primary key
		if primaryCount > 0 {
			inconsistencies = append(inconsistencies, fmt.Errorf("keyset handle has no primary key, but metadata key ID %d has state PRIMARY", metadataPrimaryID))
		}
	}

	// --- 3. Status Alignment ---
	for kID, tinkInfo := range tinkKeyIDs {
		meta, metaExists := metadataKeyIDs[kID]
		// If metadata doesn't exist, it was already flagged in check #1. Skip status check.
		if !metaExists {
			continue
		}

		tinkStatus := tinkInfo.GetStatus()
		metaState := meta.State

		// Check for contradictions based on metadata state
		switch metaState {
		case tinkrotatev1.KeyState_KEY_STATE_PENDING, tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT:
			// Should be ENABLED in Tink
			if tinkStatus != tinkpb.KeyStatusType_ENABLED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: metadata state is %s, but Tink status is %s (expected ENABLED)", kID, metaState, tinkStatus))
			}
		case tinkrotatev1.KeyState_KEY_STATE_PRIMARY:
			// Should be ENABLED in Tink (and match primary ID, checked above)
			if tinkStatus != tinkpb.KeyStatusType_ENABLED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: metadata state is PRIMARY, but Tink status is %s (expected ENABLED)", kID, tinkStatus))
			}
		case tinkrotatev1.KeyState_KEY_STATE_DISABLED:
			// Should be DISABLED in Tink
			if tinkStatus != tinkpb.KeyStatusType_DISABLED {
				// Allow ENABLED/UNKNOWN only if RAW key? No, Tink disables non-raw keys too.
				// If it's ENABLED, that's a definite mismatch. If DESTROYED, it shouldn't be in tinkKeyIDs.
				if tinkStatus != tinkpb.KeyStatusType_DESTROYED {
					inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: metadata state is DISABLED, but Tink status is %s (expected DISABLED or DESTROYED)", kID, tinkStatus))
				}
			}
		case tinkrotatev1.KeyState_KEY_STATE_UNSPECIFIED:
			inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: metadata state is UNSPECIFIED", kID))
		}

		// Check for contradictions based on Tink status
		switch tinkStatus {
		case tinkpb.KeyStatusType_ENABLED:
			if metaState != tinkrotatev1.KeyState_KEY_STATE_PENDING && metaState != tinkrotatev1.KeyState_KEY_STATE_PRIMARY && metaState != tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT {
				inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: Tink status is ENABLED, but metadata state is %s (expected PENDING, PRIMARY, or PHASING_OUT)", kID, metaState))
			}
		case tinkpb.KeyStatusType_DISABLED:
			if metaState != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: Tink status is DISABLED, but metadata state is %s (expected DISABLED)", kID, metaState))
			}
		case tinkpb.KeyStatusType_DESTROYED:
			// This case means the key is in KeysetInfo but marked as DESTROYED.
			// Metadata should ideally reflect this by being in DISABLED state and due for removal, or already removed.
			// If metadata still exists and isn't DISABLED, it's an inconsistency.
			if metaState != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: Tink status is DESTROYED, but metadata state is %s (expected DISABLED or metadata to be removed)", kID, metaState))
			}
			// If key is DESTROYED, it might be fine for metadata to be KEY_STATE_DISABLED.
			// The key will be removed from metadata by the deletion logic in RotateKeyset.
		case tinkpb.KeyStatusType_UNKNOWN_STATUS:
			logger.Warn("Key found with UNKNOWN_STATUS in Tink.", "keyID", kID)
		}
	}

	return inconsistencies
}
