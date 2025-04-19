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

// RotationPolicy ... (remains the same) ...
type RotationPolicy struct {
	KeyTemplate         *tinkpb.KeyTemplate
	PrimaryDuration     time.Duration
	PropagationTime     time.Duration
	PhaseOutDuration    time.Duration
	DeletionGracePeriod time.Duration
}

// Rotator manages the automated rotation of keys in a Tink KeysetHandle
// based on a defined policy and associated metadata.
type Rotator struct {
	Policy RotationPolicy
	now    func() time.Time // Function to get current time, allows mocking
}

// NewRotator creates a rotator instance with a given policy.
func NewRotator(policy RotationPolicy) (*Rotator, error) {
	if policy.KeyTemplate == nil {
		return nil, errors.New("key template must be provided in rotation policy")
	}
	if policy.PrimaryDuration <= 0 || policy.PropagationTime < 0 || policy.PhaseOutDuration < 0 || policy.DeletionGracePeriod < 0 {
		// Allow zero propagation time, but not negative. Primary must be positive.
		return nil, errors.New("primary duration must be positive; other durations cannot be negative")
	}
	if policy.PropagationTime > policy.PrimaryDuration {
		// Allow propagation == primary duration (immediate rotation after propagation)
		// return nil, errors.New("propagation time cannot be longer than primary duration")
	}
	return &Rotator{
		Policy: policy,
		now:    time.Now, // Default to real time
	}, nil
}

// RotateKeyset performs one rotation cycle based on the rotator's internal time source.
// It takes the current keyset handle and its corresponding metadata,
// applies the rotation policy, and returns the potentially modified
// keyset handle and updated metadata.
// The caller is responsible for persisting the returned handle and metadata.
func (r *Rotator) RotateKeyset(
	handle *keyset.Handle,
	metadata *tinkrotatev1.KeyRotationMetadata,
	// currentTime time.Time, // No longer needed as argument
) (*keyset.Handle, *tinkrotatev1.KeyRotationMetadata, error) {

	// Use the internal time source
	currentTime := r.now()

	// ... rest of the function implementation remains the same ...
	// ... (using currentTime variable internally) ...

	if handle == nil {
		return nil, nil, errors.New("keyset handle cannot be nil")
	}
	// Ensure metadata map exists
	if metadata == nil {
		metadata = &tinkrotatev1.KeyRotationMetadata{}
	}
	if metadata.KeyMetadata == nil {
		metadata.KeyMetadata = make(map[uint32]*tinkrotatev1.KeyMetadata)
	}

	inconsistencies := CheckConsistency(handle, metadata)
	if len(inconsistencies) > 0 {
		return nil, nil, fmt.Errorf("inconsistencies found in keyset handle and metadata: %v", inconsistencies)
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

		// If metadata doesn't exist for a key in the keyset, log a warning but skip processing it.
		// A robust system needs a strategy for bootstrapping metadata for existing keys.
		if !metaExists {
			fmt.Printf("[RotateKeyset Warning] Key ID %d found in keyset but not in metadata. Skipping.\n", keyID)
			continue // Skip keys we don't have metadata for
		}

		// Ensure Tink status aligns somewhat with metadata state (basic check)
		// Note: This check is informational; the logic primarily trusts the metadata state.
		currentState := meta.State
		currentStatus := keyInfo.GetStatus()
		if currentState == tinkrotatev1.KeyState_KEY_STATE_PRIMARY && currentStatus != tinkpb.KeyStatusType_ENABLED && keyInfo.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW { // Primary must be enabled (unless RAW key) - Tink enforces this via SetPrimary
			// Tink's SetPrimary usually ensures the key is ENABLED. This might catch edge cases.
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

		// Classify based on metadata state
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

	// Sort pending keys by creation time (oldest first)
	sort.Slice(pendingKeys, func(i, j int) bool {
		// Handle potential nil creation times defensively, though they shouldn't occur in normal operation
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
		// Check if metadata exists and deletion time is set
		if ki.Metadata == nil || ki.Metadata.DeletionTime == nil {
			fmt.Printf("[RotateKeyset Warning] Disabled key %d missing metadata or deletion time. Skipping deletion check.\n", ki.KeyID)
			continue
		}

		if !currentTime.Before(ki.Metadata.DeletionTime.AsTime()) {
			// Check Tink status before attempting deletion
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
					// Decide whether to continue or return error. Continuing allows other rotations.
				} else {
					keysToDelete = append(keysToDelete, ki.KeyID) // Mark for metadata removal
					updated = true
				}
			} else {
				// Already destroyed in Tink, ensure it's marked for metadata removal
				if _, exists := metadata.KeyMetadata[ki.KeyID]; exists {
					keysToDelete = append(keysToDelete, ki.KeyID)
					updated = true // Metadata changed
				}
			}
		}
	}
	// Remove deleted keys from metadata map *after* iteration
	for _, keyID := range keysToDelete {
		delete(metadata.KeyMetadata, keyID)
	}

	// --- 2. Process Disabling (Phasing-Out -> Disabled) ---
	for _, ki := range phasingOutKeys {
		// Check metadata validity
		if ki.Metadata == nil {
			fmt.Printf("[RotateKeyset Warning] Phasing-out key %d missing metadata. Skipping disable check.\n", ki.KeyID)
			continue
		}

		// A key becomes disabled PhaseOutDuration *after the new primary was promoted*.
		// Use the promotion time of the *current* primary key.
		disableTimeKnown := false
		var expectedDisableTime time.Time
		if primaryKey != nil && primaryKey.Metadata != nil && primaryKey.Metadata.PromotionTime != nil {
			expectedDisableTime = primaryKey.Metadata.PromotionTime.AsTime().Add(r.Policy.PhaseOutDuration)
			disableTimeKnown = true
		} else {
			// Fallback: If no current primary or its promotion time is unknown,
			// use the phasing-out key's own creation + primary duration + phase-out duration.
			// This assumes it served a full primary term. Less accurate but better than nothing.
			if ki.Metadata.CreationTime != nil {
				expectedDisableTime = ki.Metadata.CreationTime.AsTime().Add(r.Policy.PrimaryDuration).Add(r.Policy.PhaseOutDuration)
				disableTimeKnown = true
				fmt.Printf("[RotateKeyset Info] Key %d using fallback disable time check.\n", ki.KeyID)
			} else {
				fmt.Printf("[RotateKeyset Warning] Phasing-out key %d missing creation time. Cannot determine disable time. Skipping.\n", ki.KeyID)
			}
		}

		if disableTimeKnown && !currentTime.Before(expectedDisableTime) {
			// Check Tink status before attempting disable
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
				// Update metadata
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				ki.Metadata.DisableTime = timestamppb.New(currentTime)
				ki.Metadata.DeletionTime = timestamppb.New(currentTime.Add(r.Policy.DeletionGracePeriod))
				updated = true
			} else if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_DISABLED && ki.Metadata.State != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				// Keyset is already disabled, update metadata to match
				fmt.Printf("[RotateKeyset Info] Aligning metadata for already disabled key %d.\n", ki.KeyID)
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				if ki.Metadata.DisableTime == nil { // Set times if not already set
					ki.Metadata.DisableTime = timestamppb.New(currentTime) // Use current time as approximation
				}
				// Ensure deletion time is set based on disable time
				if ki.Metadata.DisableTime != nil && ki.Metadata.DeletionTime == nil {
					ki.Metadata.DeletionTime = timestamppb.New(ki.Metadata.DisableTime.AsTime().Add(r.Policy.DeletionGracePeriod))
				} else if ki.Metadata.DeletionTime == nil {
					// Fallback if disable time is also missing
					ki.Metadata.DeletionTime = timestamppb.New(currentTime.Add(r.Policy.DeletionGracePeriod))
				}
				updated = true
			}
		}
	}

	// --- 3. Process Promotion (Pending -> Primary) ---
	if primaryKey != nil {
		// Check metadata validity
		if primaryKey.Metadata == nil {
			fmt.Printf("[RotateKeyset Warning] Primary key %d missing metadata. Skipping promotion check.\n", primaryKey.KeyID)
		} else {
			// Check if primary key's lifetime has expired
			primaryExpired := false
			expiryTimeKnown := false
			var expectedEndTime time.Time
			// Prefer promotion time to calculate expiry
			if primaryKey.Metadata.PromotionTime != nil {
				expectedEndTime = primaryKey.Metadata.PromotionTime.AsTime().Add(r.Policy.PrimaryDuration)
				expiryTimeKnown = true
			} else if primaryKey.Metadata.CreationTime != nil {
				// Fallback: use creation time if promotion time is missing (e.g., initial key)
				expectedEndTime = primaryKey.Metadata.CreationTime.AsTime().Add(r.Policy.PrimaryDuration)
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
					// Promote the oldest pending key that meets propagation time
					promoted := false
					for _, pendingKey := range pendingKeys {
						// Check metadata validity
						if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
							fmt.Printf("[RotateKeyset Warning] Pending key %d missing metadata or creation time. Skipping promotion check for this key.\n", pendingKey.KeyID)
							continue
						}

						// Check Tink status before attempting promotion
						tinkKeyInfo, err := findTinkKeyInfo(manager, pendingKey.KeyID)
						if err != nil {
							fmt.Printf("[RotateKeyset Warning] Could not find Tink info for pending key %d during promotion check: %v. Skipping.\n", pendingKey.KeyID, err)
							continue
						}
						if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
							fmt.Printf("[RotateKeyset Warning] Pending key %d is not ENABLED in keyset (status: %s). Skipping promotion.\n", pendingKey.KeyID, tinkKeyInfo.GetStatus())
							continue
						}

						propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(r.Policy.PropagationTime)
						if !currentTime.Before(propagationEndTime) {
							fmt.Printf("[RotateKeyset Info] Promoting key %d to PRIMARY (Primary %d expired at %s, propagation time met).\n", pendingKey.KeyID, primaryKey.KeyID, expectedEndTime.Format(time.RFC3339))
							err := manager.SetPrimary(pendingKey.KeyID)
							if err != nil {
								fmt.Printf("[RotateKeyset Error] Failed to promote key %d: %v\n", pendingKey.KeyID, err)
								// Don't break; maybe another pending key could be promoted? (Unlikely with sorted list)
								continue
							}

							// Update metadata for old primary
							primaryKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT
							// Keep primaryKey.Metadata.PromotionTime as historical record

							// Update metadata for new primary
							pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
							pendingKey.Metadata.PromotionTime = timestamppb.New(currentTime)

							updated = true
							promoted = true
							break // Promotion successful, exit loop for pending keys
						} else {
							fmt.Printf("[RotateKeyset Info] Primary key %d expired, but pending key %d hasn't met propagation time (%s remaining until %s). Waiting.\n",
								primaryKey.KeyID, pendingKey.KeyID, propagationEndTime.Sub(currentTime).Round(time.Second), propagationEndTime.Format(time.RFC3339))
							// Block promotion, wait for next cycle. Since keys are sorted, no later key will be ready either.
							break
						}
					}
					if !promoted && len(pendingKeys) > 0 { // Check if we iterated but none were ready
						fmt.Printf("[RotateKeyset Info] Primary key %d expired, but no suitable pending key ready for promotion yet.\n", primaryKey.KeyID)
					} else if len(pendingKeys) == 0 {
						fmt.Printf("[RotateKeyset Warning] Primary key %d expired, but NO PENDING key available to promote.\n", primaryKey.KeyID)
					}
				} else { // primaryExpired is true, but no pending keys
					fmt.Printf("[RotateKeyset Warning] Primary key %d expired, but NO PENDING key available to promote.\n", primaryKey.KeyID)
				}
			}
		} // end primary key metadata check
	} else { // No primary key exists
		// Promote the oldest PENDING key if available and propagation met.
		if len(pendingKeys) > 0 {
			pendingKey := pendingKeys[0] // Oldest one
			// Check metadata validity
			if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
				fmt.Printf("[RotateKeyset Warning] Pending key %d missing metadata or creation time. Cannot promote.\n", pendingKey.KeyID)
			} else {
				// Check Tink status
				tinkKeyInfo, err := findTinkKeyInfo(manager, pendingKey.KeyID)
				if err != nil {
					fmt.Printf("[RotateKeyset Warning] Could not find Tink info for pending key %d during initial promotion check: %v. Skipping.\n", pendingKey.KeyID, err)
				} else if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
					fmt.Printf("[RotateKeyset Warning] Pending key %d is not ENABLED (status: %s). Cannot promote.\n", pendingKey.KeyID, tinkKeyInfo.GetStatus())
				} else {
					propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(r.Policy.PropagationTime)
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
			// Rotation can't proceed. Need manual intervention or bootstrap logic.
		}
	}

	// Refresh primaryKey and pending status after potential promotion/generation
	ksInfoHandle, err := manager.Handle()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get updated handle from manager: %w", err)
	}
	ksInfo = ksInfoHandle.KeysetInfo() // Get potentially updated info
	primaryKey = nil                   // Reset and find again
	hasPending := false
	for _, keyInfo := range ksInfo.GetKeyInfo() {
		meta, exists := metadata.KeyMetadata[keyInfo.GetKeyId()]
		if !exists {
			continue
		} // Ignore keys without metadata

		// Use the keyInfos map built earlier if the keyID exists there
		currentKeyInfo, kiExists := keyInfos[keyInfo.GetKeyId()]
		if !kiExists {
			// If a key was just added, it won't be in the initial keyInfos map
			currentKeyInfo = &KeyInfo{
				KeyID:    keyInfo.GetKeyId(),
				Status:   keyInfo.GetStatus(),
				Metadata: meta,
			}
			keyInfos[keyInfo.GetKeyId()] = currentKeyInfo // Add it now
		} else {
			// Update status from potentially modified keyset handle
			currentKeyInfo.Status = keyInfo.GetStatus()
		}

		if meta.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			// Ensure Tink agrees it's primary
			if keyInfo.GetKeyId() == ksInfo.GetPrimaryKeyId() {
				primaryKey = currentKeyInfo
			} else {
				fmt.Printf("[RotateKeyset Warning] Metadata state for key %d is PRIMARY, but Tink primary is %d. Correcting metadata.\n", keyInfo.GetKeyId(), ksInfo.GetPrimaryKeyId())
				// This key is likely phasing out now
				meta.State = tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT
				meta.PromotionTime = nil // Clear promotion time as it's no longer primary
				updated = true
			}
		}
		if meta.State == tinkrotatev1.KeyState_KEY_STATE_PENDING {
			hasPending = true
		}
	}
	// If after checks, primaryKey is still nil, but Tink has a primary ID, update metadata
	if primaryKey == nil && ksInfo.GetPrimaryKeyId() != 0 {
		tinkPrimaryId := ksInfo.GetPrimaryKeyId()
		meta, exists := metadata.KeyMetadata[tinkPrimaryId]
		if exists {
			fmt.Printf("[RotateKeyset Warning] Tink primary is %d, but no key had PRIMARY metadata state. Setting metadata state for %d to PRIMARY.\n", tinkPrimaryId, tinkPrimaryId)
			meta.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
			if meta.PromotionTime == nil { // Set promotion time if missing
				meta.PromotionTime = timestamppb.New(currentTime)
			}
			primaryKey = keyInfos[tinkPrimaryId] // Update local variable
			updated = true
		} else {
			fmt.Printf("[RotateKeyset Error] Tink primary key %d has no corresponding metadata!\n", tinkPrimaryId)
			// This is a critical inconsistency.
		}
	}

	// --- 4. Generate New Pending Key ---
	// Generate if there's a primary key and no pending key currently exists.
	if primaryKey != nil && !hasPending {
		fmt.Printf("[RotateKeyset Info] Generating new PENDING key (Primary %d exists, no pending key found).\n", primaryKey.KeyID)
		keyID, err := manager.Add(r.Policy.KeyTemplate)
		if err != nil {
			return nil, nil, fmt.Errorf("[RotateKeyset Error] Failed to add new key data to manager: %v", err)
		}
		// Create metadata for the new key
		newMeta := &tinkrotatev1.KeyMetadata{
			KeyId:        keyID,
			State:        tinkrotatev1.KeyState_KEY_STATE_PENDING,
			CreationTime: timestamppb.New(currentTime),
			// PromotionTime, DisableTime, DeletionTime are initially nil
		}
		metadata.KeyMetadata[keyID] = newMeta // Add to metadata map
		updated = true
		fmt.Printf("[RotateKeyset Info] Generated new PENDING key %d.\n", keyID)
	}

	// --- Return updated handle and metadata ---
	var finalHandle *keyset.Handle
	if updated {
		// Get the potentially modified handle from the manager
		finalHandle, err = manager.Handle()
		if err != nil {
			// Return the original handle and metadata along with the error
			return handle, metadata, fmt.Errorf("failed to get updated handle from manager: %w", err)
		}
	} else {
		finalHandle = handle // No changes, return original handle
	}

	// Return the latest handle and the potentially updated metadata map
	return finalHandle, metadata, nil
}

// Helper to find Tink KeyInfo within a manager/handle
// Note: This requires getting the handle info repeatedly, might be inefficient for many calls.
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

// KeyInfo helper struct (remains the same)
type KeyInfo struct {
	KeyID    uint32
	Status   tinkpb.KeyStatusType
	Metadata *tinkrotatev1.KeyMetadata
}

// CheckConsistency verifies that the state represented in the KeysetHandle
// matches the state described in the KeyRotationMetadata.
// It returns a slice of errors describing any inconsistencies found.
// An empty slice indicates that the handle and metadata are consistent.
func CheckConsistency(handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata) []error {
	var inconsistencies []error

	if handle == nil {
		inconsistencies = append(inconsistencies, errors.New("keyset handle is nil"))
		// Cannot proceed further if handle is nil
		return inconsistencies
	}
	ksInfo := handle.KeysetInfo()

	// Handle potentially nil metadata or metadata map
	if metadata == nil {
		// If the handle is not empty, having nil metadata is an inconsistency
		if len(ksInfo.GetKeyInfo()) > 0 {
			inconsistencies = append(inconsistencies, errors.New("metadata is nil, but keyset handle contains keys"))
		}
		// Return early if metadata is nil
		return inconsistencies
	}
	if metadata.KeyMetadata == nil {
		// Treat a nil map like an empty map
		metadata.KeyMetadata = make(map[uint32]*tinkrotatev1.KeyMetadata)
		if len(ksInfo.GetKeyInfo()) > 0 {
			inconsistencies = append(inconsistencies, errors.New("metadata map is nil/empty, but keyset handle contains keys"))
			// Can continue checking from the perspective of keyset keys below
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
