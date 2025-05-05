package tinkrotate

import (
	"errors"
	"fmt"
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

// RotateKeyset performs one rotation cycle based on the provided current time.
// It reads the rotation policy *from the metadata* itself.
// It takes the current keyset handle and its corresponding metadata,
// applies the rotation policy, and returns the potentially modified
// keyset handle and updated metadata.
// The caller is responsible for persisting the returned handle and metadata.
func RotateKeyset(
	currentTime time.Time, // Use explicit time
	handle *keyset.Handle,
	metadata *tinkrotatev1.KeyRotationMetadata,
) (*keyset.Handle, *tinkrotatev1.KeyRotationMetadata, error) {

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
			fmt.Printf("[RotateKeyset Warning] Key ID %d found in keyset but not in metadata. Skipping.\n", keyID)
			continue
		}

		currentState := meta.State
		currentStatus := keyInfo.GetStatus()
		if currentState == tinkrotatev1.KeyState_KEY_STATE_PRIMARY && currentStatus != tinkpb.KeyStatusType_ENABLED && keyInfo.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW { // Primary must be enabled (unless RAW key) - Tink enforces this via SetPrimary
			fmt.Printf("[RotateKeyset Warning] Key ID %d metadata state is PRIMARY, but Tink status is %s.\n", keyID, currentStatus)
		}
		if (currentState == tinkrotatev1.KeyState_KEY_STATE_PENDING || currentState == tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT) && currentStatus != tinkpb.KeyStatusType_ENABLED {
			fmt.Printf("[RotateKeyset Warning] Key ID %d metadata state is %s, but Tink status is %s. Should be ENABLED.\n", keyID, currentState, currentStatus)
		}
		if currentState == tinkrotatev1.KeyState_KEY_STATE_DISABLED && currentStatus != tinkpb.KeyStatusType_DISABLED {
			fmt.Printf("[RotateKeyset Warning] Key ID %d metadata state is DISABLED, but Tink status is %s. Should be DISABLED.\n", keyID, currentStatus)
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
				fmt.Printf("[RotateKeyset Warning] Multiple keys (%d, %d) marked as PRIMARY in metadata. Using first encountered (%d).\n", primaryKey.KeyID, ki.KeyID, primaryKey.KeyID)
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
			fmt.Printf("[RotateKeyset Warning] Disabled key %d missing metadata or deletion time. Skipping deletion check.\n", ki.KeyID)
			continue
		}

		if !currentTime.Before(ki.Metadata.DeletionTime.AsTime()) {
			tinkKeyInfo, err := findTinkKeyInfo(manager, ki.KeyID)
			if err != nil {
				fmt.Printf("[RotateKeyset Warning] Could not find Tink info for key %d during deletion check: %v. Skipping.\n", ki.KeyID, err)
				continue
			}

			if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_DESTROYED {
				fmt.Printf("[RotateKeyset Info] Deleting key %d (past deletion time %s).\n", ki.KeyID, ki.Metadata.DeletionTime.AsTime().Format(time.RFC3339))
				err := manager.Delete(ki.KeyID)
				if err != nil {
					fmt.Printf("[RotateKeyset Error] Failed to delete key %d: %v\n", ki.KeyID, err)
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
			fmt.Printf("[RotateKeyset Warning] Phasing-out key %d missing metadata. Skipping disable check.\n", ki.KeyID)
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
				fmt.Printf("[RotateKeyset Info] Key %d using fallback disable time check.\n", ki.KeyID)
			} else {
				fmt.Printf("[RotateKeyset Warning] Phasing-out key %d missing creation time. Cannot determine disable time. Skipping.\n", ki.KeyID)
			}
		}

		if disableTimeKnown && !currentTime.Before(expectedDisableTime) {
			tinkKeyInfo, err := findTinkKeyInfo(manager, ki.KeyID)
			if err != nil {
				fmt.Printf("[RotateKeyset Warning] Could not find Tink info for key %d during disable check: %v. Skipping.\n", ki.KeyID, err)
				continue
			}

			if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_ENABLED {
				fmt.Printf("[RotateKeyset Info] Disabling key %d (phase-out period ended at %s).\n", ki.KeyID, expectedDisableTime.Format(time.RFC3339))
				err := manager.Disable(ki.KeyID)
				if err != nil {
					fmt.Printf("[RotateKeyset Error] Failed to disable key %d: %v\n", ki.KeyID, err)
					continue // Skip metadata update on error
				}
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				ki.Metadata.DisableTime = timestamppb.New(currentTime)
				ki.Metadata.DeletionTime = timestamppb.New(currentTime.Add(deletionGracePeriod))
				updated = true
			} else if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_DISABLED && ki.Metadata.State != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				fmt.Printf("[RotateKeyset Info] Aligning metadata for already disabled key %d.\n", ki.KeyID)
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
			fmt.Printf("[RotateKeyset Warning] Primary key %d missing metadata. Skipping promotion check.\n", primaryKey.KeyID)
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
				fmt.Printf("[RotateKeyset Warning] Primary key %d missing promotion time. Using creation time for expiry check.\n", primaryKey.KeyID)
			} else {
				fmt.Printf("[RotateKeyset Warning] Primary key %d missing both promotion and creation time. Cannot check expiry.\n", primaryKey.KeyID)
			}

			if expiryTimeKnown && !currentTime.Before(expectedEndTime) {
				primaryExpired = true
			}

			if primaryExpired {
				if len(pendingKeys) > 0 {
					promoted := false
					for _, pendingKey := range pendingKeys {
						if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
							fmt.Printf("[RotateKeyset Warning] Pending key %d missing metadata or creation time. Skipping promotion check for this key.\n", pendingKey.KeyID)
							continue
						}

						tinkKeyInfo, err := findTinkKeyInfo(manager, pendingKey.KeyID)
						if err != nil {
							fmt.Printf("[RotateKeyset Warning] Could not find Tink info for pending key %d during promotion check: %v. Skipping.\n", pendingKey.KeyID, err)
							continue
						}
						if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
							fmt.Printf("[RotateKeyset Warning] Pending key %d is not ENABLED in keyset (status: %s). Skipping promotion.\n", pendingKey.KeyID, tinkKeyInfo.GetStatus())
							continue
						}

						propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(propagationTime)
						if !currentTime.Before(propagationEndTime) {
							fmt.Printf("[RotateKeyset Info] Promoting key %d to PRIMARY (Primary %d expired at %s, propagation time met).\n", pendingKey.KeyID, primaryKey.KeyID, expectedEndTime.Format(time.RFC3339))
							err := manager.SetPrimary(pendingKey.KeyID)
							if err != nil {
								fmt.Printf("[RotateKeyset Error] Failed to promote key %d: %v\n", pendingKey.KeyID, err)
								continue
							}

							primaryKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT

							pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
							pendingKey.Metadata.PromotionTime = timestamppb.New(currentTime)

							updated = true
							promoted = true
							break // Promotion successful
						} else {
							fmt.Printf("[RotateKeyset Info] Primary key %d expired, but pending key %d hasn't met propagation time (%s remaining until %s). Waiting.\n",
								primaryKey.KeyID, pendingKey.KeyID, propagationEndTime.Sub(currentTime).Round(time.Second), propagationEndTime.Format(time.RFC3339))
							break // Block promotion, wait for next cycle
						}
					}
					if !promoted && len(pendingKeys) > 0 {
						fmt.Printf("[RotateKeyset Info] Primary key %d expired, but no suitable pending key ready for promotion yet.\n", primaryKey.KeyID)
					} else if len(pendingKeys) == 0 {
						fmt.Printf("[RotateKeyset Warning] Primary key %d expired, but NO PENDING key available to promote.\n", primaryKey.KeyID)
					}
				} else {
					fmt.Printf("[RotateKeyset Warning] Primary key %d expired, but NO PENDING key available to promote.\n", primaryKey.KeyID)
				}
			}
		}
	} else { // No primary key exists
		if len(pendingKeys) > 0 {
			pendingKey := pendingKeys[0] // Oldest one
			if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
				fmt.Printf("[RotateKeyset Warning] Pending key %d missing metadata or creation time. Cannot promote.\n", pendingKey.KeyID)
			} else {
				tinkKeyInfo, err := findTinkKeyInfo(manager, pendingKey.KeyID)
				if err != nil {
					fmt.Printf("[RotateKeyset Warning] Could not find Tink info for pending key %d during initial promotion check: %v. Skipping.\n", pendingKey.KeyID, err)
				} else if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
					fmt.Printf("[RotateKeyset Warning] Pending key %d is not ENABLED (status: %s). Cannot promote.\n", pendingKey.KeyID, tinkKeyInfo.GetStatus())
				} else {
					propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(propagationTime)
					if !currentTime.Before(propagationEndTime) {
						fmt.Printf("[RotateKeyset Info] Promoting key %d to PRIMARY (no primary exists, propagation time met).\n", pendingKey.KeyID)
						err := manager.SetPrimary(pendingKey.KeyID)
						if err != nil {
							fmt.Printf("[RotateKeyset Error] Failed to promote key %d: %v\n", pendingKey.KeyID, err)
						} else {
							pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
							pendingKey.Metadata.PromotionTime = timestamppb.New(currentTime)
							updated = true
						}
					} else {
						fmt.Printf("[RotateKeyset Info] No primary key, pending key %d not ready for promotion (%s remaining until %s).\n",
							pendingKey.KeyID, propagationEndTime.Sub(currentTime).Round(time.Second), propagationEndTime.Format(time.RFC3339))
					}
				}
			}
		} else {
			fmt.Println("[RotateKeyset Info] No primary key and no pending keys found.")
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
				fmt.Printf("[RotateKeyset Warning] Metadata state for key %d is PRIMARY, but Tink primary is %d. Setting state to PHASING_OUT.\n", keyInfo.GetKeyId(), ksInfo.GetPrimaryKeyId())
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
				fmt.Printf("[RotateKeyset Warning] Tink primary is %d, but its metadata state was %s. Setting metadata state to PRIMARY.\n", tinkPrimaryId, meta.State)
				meta.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
				if meta.PromotionTime == nil { // Set promotion time if missing
					meta.PromotionTime = timestamppb.New(currentTime)
				}
				primaryKey = keyInfos[tinkPrimaryId] // Update local variable
				updated = true
			}
			// If state was already primary, primaryKey should have been set unless keyInfos map was incomplete
		} else {
			fmt.Printf("[RotateKeyset Error] Tink primary key %d has no corresponding metadata!\n", tinkPrimaryId)
			// This is a critical inconsistency, potentially halt? For now, we logged the error.
		}
	}

	// --- 4. Generate New Pending Key ---
	if primaryKey != nil && !hasPending {
		fmt.Printf("[RotateKeyset Info] Generating new PENDING key (Primary %d exists, no pending key found).\n", primaryKey.KeyID)
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
		fmt.Printf("[RotateKeyset Info] Generated new PENDING key %d.\n", keyID)
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
		fmt.Printf("[RotateKeyset Warning] Inconsistencies found *after* rotation attempt: %v. Returning potentially inconsistent state.\n", finalInconsistencies)
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
				inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: metadata state is DISABLED, but Tink status is %s (expected DISABLED)", kID, tinkStatus))
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
			// This case shouldn't be reachable as destroyed keys shouldn't be in tinkKeyIDs
			inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d: Found in Tink KeyInfo with status DESTROYED (should have been filtered)", kID))
		case tinkpb.KeyStatusType_UNKNOWN_STATUS:
			// Handle unknown status? Maybe just log it.
		}
	}

	return inconsistencies
}
