package tinkrotate

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
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
// It reads the rotation policy from the metadata itself.
// The caller is responsible for persisting the returned handle and metadata.
func RotateKeyset(
	handle *keyset.Handle,
	metadata *tinkrotatev1.KeyRotationMetadata,
	opts *RotateOpts,
) (*keyset.Handle, *tinkrotatev1.KeyRotationMetadata, bool, error) {

	var logger *slog.Logger
	if opts != nil && opts.Logger != nil {
		logger = opts.Logger
	} else {
		logger = slog.New(slog.DiscardHandler)
	}
	logger = logger.With("function", "RotateKeyset")

	if handle == nil {
		return nil, nil, false, errors.New("keyset handle cannot be nil")
	}
	if metadata == nil {
		if len(handle.KeysetInfo().GetKeyInfo()) > 0 {
			return nil, nil, false, errors.New("metadata cannot be nil for non-empty keyset")
		}
		metadata = &tinkrotatev1.KeyRotationMetadata{}
	}
	if metadata.KeyMetadata == nil {
		metadata.KeyMetadata = make(map[uint32]*tinkrotatev1.KeyMetadata)
	}

	policy := metadata.RotationPolicy
	if err := ValidateRotationPolicy(policy); err != nil {
		return nil, nil, false, fmt.Errorf("invalid rotation policy in metadata: %w", err)
	}

	inconsistencies := CheckConsistency(handle, metadata)
	if len(inconsistencies) > 0 {
		return nil, nil, false, fmt.Errorf("inconsistencies found before rotation: %v", inconsistencies)
	}

	r := &rotator{
		handle:   handle,
		metadata: metadata,
		manager:  keyset.NewManagerFromHandle(handle),
		opts:     opts,
		logger:   logger,
		policy:   policy,
		now:      time.Now(),
	}

	if opts != nil && opts.TimeSource != nil {
		r.now = opts.TimeSource()
	}

	if err := r.init(); err != nil {
		return nil, nil, false, err
	}

	if err := r.handleDeletions(); err != nil {
		return nil, nil, false, err
	}
	if err := r.handlePhaseOut(); err != nil {
		return nil, nil, false, err
	}
	if err := r.handlePromotions(); err != nil {
		return nil, nil, false, err
	}
	if err := r.handleKeyGeneration(); err != nil {
		return nil, nil, false, err
	}

	finalHandle := r.handle
	var err error
	if r.updated {
		finalHandle, err = r.manager.Handle()
		if err != nil {
			return nil, nil, r.updated, fmt.Errorf("failed to get final handle: %w", err)
		}
	}

	finalInconsistencies := CheckConsistency(finalHandle, metadata)
	if len(finalInconsistencies) > 0 {
		logger.Warn("Inconsistencies found after rotation attempt.", "inconsistencies", finalInconsistencies)
	}

	return finalHandle, metadata, r.updated, nil
}

type rotator struct {
	handle   *keyset.Handle
	metadata *tinkrotatev1.KeyRotationMetadata
	manager  *keyset.Manager
	opts     *RotateOpts
	logger   *slog.Logger
	policy   *tinkrotatev1.RotationPolicy
	now      time.Time
	updated  bool

	primaryKey     *KeyInfo
	pendingKeys    []*KeyInfo
	phasingOutKeys []*KeyInfo
	disabledKeys   []*KeyInfo
}

func (r *rotator) init() error {
	ksInfo := r.handle.KeysetInfo()
	for _, keyInfo := range ksInfo.GetKeyInfo() {
		keyID := keyInfo.GetKeyId()
		meta, exists := r.metadata.KeyMetadata[keyID]
		if !exists {
			r.logger.Warn("Key ID found in keyset but not in metadata. Skipping.", "keyID", keyID)
			continue
		}

		ki := &KeyInfo{
			KeyID:    keyID,
			Status:   keyInfo.GetStatus(),
			Metadata: meta,
		}

		switch meta.State {
		case tinkrotatev1.KeyState_KEY_STATE_PRIMARY:
			if r.primaryKey != nil {
				r.logger.Warn("Multiple keys marked as PRIMARY in metadata. Using first encountered.", "existing_primary", r.primaryKey.KeyID, "new_primary", ki.KeyID)
			} else {
				r.primaryKey = ki
			}
		case tinkrotatev1.KeyState_KEY_STATE_PENDING:
			r.pendingKeys = append(r.pendingKeys, ki)
		case tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT:
			r.phasingOutKeys = append(r.phasingOutKeys, ki)
		case tinkrotatev1.KeyState_KEY_STATE_DISABLED:
			r.disabledKeys = append(r.disabledKeys, ki)
		}
	}

	sort.Slice(r.pendingKeys, func(i, j int) bool {
		t1 := time.Time{}
		if r.pendingKeys[i].Metadata.CreationTime != nil {
			t1 = r.pendingKeys[i].Metadata.CreationTime.AsTime()
		}
		t2 := time.Time{}
		if r.pendingKeys[j].Metadata.CreationTime != nil {
			t2 = r.pendingKeys[j].Metadata.CreationTime.AsTime()
		}
		return t1.Before(t2)
	})
	return nil
}

func (r *rotator) handleDeletions() error {
	keysToDelete := []uint32{}
	for _, ki := range r.disabledKeys {
		if ki.Metadata == nil || ki.Metadata.DeletionTime == nil {
			continue
		}

		if !r.now.Before(ki.Metadata.DeletionTime.AsTime()) {
			tinkKeyInfo, err := findTinkKeyInfo(r.manager, ki.KeyID)
			if err != nil {
				continue
			}

			if tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_DESTROYED {
				r.logger.Info("Deleting key (past deletion time).", "keyID", ki.KeyID)
				if err := r.manager.Delete(ki.KeyID); err != nil {
					r.logger.Error("Failed to delete key.", "keyID", ki.KeyID, "error", err)
				} else {
					keysToDelete = append(keysToDelete, ki.KeyID)
					r.updated = true
				}
			} else {
				keysToDelete = append(keysToDelete, ki.KeyID)
				r.updated = true
			}
		}
	}
	for _, keyID := range keysToDelete {
		delete(r.metadata.KeyMetadata, keyID)
	}
	return nil
}

func (r *rotator) handlePhaseOut() error {
	phaseOutDuration := r.policy.PhaseOutDuration.AsDuration()
	primaryDuration := r.policy.PrimaryDuration.AsDuration()
	deletionGracePeriod := r.policy.DeletionGracePeriod.AsDuration()

	for _, ki := range r.phasingOutKeys {
		if ki.Metadata == nil {
			continue
		}

		var expectedDisableTime time.Time
		disableTimeKnown := false

		if r.primaryKey != nil && r.primaryKey.Metadata != nil && r.primaryKey.Metadata.PromotionTime != nil {
			expectedDisableTime = r.primaryKey.Metadata.PromotionTime.AsTime().Add(phaseOutDuration)
			disableTimeKnown = true
		} else if ki.Metadata.CreationTime != nil {
			// Fallback
			expectedDisableTime = ki.Metadata.CreationTime.AsTime().Add(primaryDuration).Add(phaseOutDuration)
			disableTimeKnown = true
		}

		if disableTimeKnown && !r.now.Before(expectedDisableTime) {
			tinkKeyInfo, err := findTinkKeyInfo(r.manager, ki.KeyID)
			if err != nil {
				continue
			}

			if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_ENABLED {
				r.logger.Info("Disabling key (phase-out period ended).", "keyID", ki.KeyID)
				if err := r.manager.Disable(ki.KeyID); err != nil {
					r.logger.Error("Failed to disable key.", "keyID", ki.KeyID, "error", err)
					continue
				}
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				ki.Metadata.DisableTime = timestamppb.New(r.now)
				ki.Metadata.DeletionTime = timestamppb.New(r.now.Add(deletionGracePeriod))
				r.updated = true
			} else if tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_DISABLED && ki.Metadata.State != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				ki.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_DISABLED
				if ki.Metadata.DisableTime == nil {
					ki.Metadata.DisableTime = timestamppb.New(r.now)
				}
				if ki.Metadata.DeletionTime == nil {
					ki.Metadata.DeletionTime = timestamppb.New(ki.Metadata.DisableTime.AsTime().Add(deletionGracePeriod))
				}
				r.updated = true
			}
		}
	}
	return nil
}

func (r *rotator) handlePromotions() error {
	primaryDuration := r.policy.PrimaryDuration.AsDuration()
	propagationTime := r.policy.PropagationTime.AsDuration()

	if r.primaryKey != nil {
		if r.primaryKey.Metadata == nil {
			return nil
		}

		var expectedEndTime time.Time
		expired := false

		if r.primaryKey.Metadata.PromotionTime != nil {
			expectedEndTime = r.primaryKey.Metadata.PromotionTime.AsTime().Add(primaryDuration)
			if !r.now.Before(expectedEndTime) {
				expired = true
			}
		} else if r.primaryKey.Metadata.CreationTime != nil {
			expectedEndTime = r.primaryKey.Metadata.CreationTime.AsTime().Add(primaryDuration)
			if !r.now.Before(expectedEndTime) {
				expired = true
			}
		}

		if expired && len(r.pendingKeys) > 0 {
			for _, pendingKey := range r.pendingKeys {
				if pendingKey.Metadata == nil || pendingKey.Metadata.CreationTime == nil {
					continue
				}

				tinkKeyInfo, err := findTinkKeyInfo(r.manager, pendingKey.KeyID)
				if err != nil || tinkKeyInfo.GetStatus() != tinkpb.KeyStatusType_ENABLED {
					continue
				}

				propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(propagationTime)
				if !r.now.Before(propagationEndTime) {
					r.logger.Info("Promoting key to PRIMARY.", "keyID", pendingKey.KeyID)
					if err := r.manager.SetPrimary(pendingKey.KeyID); err != nil {
						r.logger.Error("Failed to promote key.", "keyID", pendingKey.KeyID, "error", err)
						continue
					}

					r.primaryKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT
					pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
					pendingKey.Metadata.PromotionTime = timestamppb.New(r.now)

					r.updated = true
					// Update primaryKey pointer for subsequent logic if needed,
					// but for now just breaking is fine as we only promote one per cycle.
					return nil
				}
			}
		}
	} else if len(r.pendingKeys) > 0 {
		// No primary key, promote oldest pending if ready
		pendingKey := r.pendingKeys[0]
		if pendingKey.Metadata != nil && pendingKey.Metadata.CreationTime != nil {
			propagationEndTime := pendingKey.Metadata.CreationTime.AsTime().Add(propagationTime)
			if !r.now.Before(propagationEndTime) {
				tinkKeyInfo, err := findTinkKeyInfo(r.manager, pendingKey.KeyID)
				if err == nil && tinkKeyInfo.GetStatus() == tinkpb.KeyStatusType_ENABLED {
					r.logger.Info("Promoting key to PRIMARY (initial).", "keyID", pendingKey.KeyID)
					if err := r.manager.SetPrimary(pendingKey.KeyID); err != nil {
						r.logger.Error("Failed to promote key.", "keyID", pendingKey.KeyID, "error", err)
					} else {
						pendingKey.Metadata.State = tinkrotatev1.KeyState_KEY_STATE_PRIMARY
						pendingKey.Metadata.PromotionTime = timestamppb.New(r.now)
						r.updated = true
						// We now have a primary key, but for this cycle we are done with promotions.
					}
				}
			}
		}
	}
	return nil
}

func (r *rotator) handleKeyGeneration() error {
	// Re-check primary/pending status from the manager because promotions might have happened.
	// But actually, we only updated metadata in memory.
	// The logic: "If primaryKey != nil && !hasPending"

	// We need to know if there is *currently* a pending key.
	// We can check our r.pendingKeys list.
	// BUT, if we just promoted a pending key to primary, it is no longer pending.
	// So we need to re-evaluate based on the *current* state of metadata in `r`.

	hasPending := false
	hasPrimary := false

	// Scan our tracked keys to see their current (possibly updated) state
	allKeys := append([]*KeyInfo{}, r.primaryKey) // Primary might be nil
	allKeys = append(allKeys, r.pendingKeys...)
	allKeys = append(allKeys, r.phasingOutKeys...)
	allKeys = append(allKeys, r.disabledKeys...)

	for _, k := range allKeys {
		if k == nil || k.Metadata == nil {
			continue
		}
		if k.Metadata.State == tinkrotatev1.KeyState_KEY_STATE_PENDING {
			hasPending = true
		}
		if k.Metadata.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			hasPrimary = true
		}
	}

	if hasPrimary && !hasPending {
		r.logger.Info("Generating new PENDING key.")
		keyID, err := r.manager.Add(r.policy.KeyTemplate)
		if err != nil {
			return fmt.Errorf("failed to add new key: %w", err)
		}

		newMeta := &tinkrotatev1.KeyMetadata{
			KeyId:        keyID,
			State:        tinkrotatev1.KeyState_KEY_STATE_PENDING,
			CreationTime: timestamppb.New(r.now),
		}
		r.metadata.KeyMetadata[keyID] = newMeta
		r.updated = true
		r.logger.Info("Generated new PENDING key.", "keyID", keyID)
	}

	return nil
}

// Helper to find Tink KeyInfo within a manager/handle
func findTinkKeyInfo(m *keyset.Manager, keyID uint32) (*tinkpb.KeysetInfo_KeyInfo, error) {
	h, err := m.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get handle: %w", err)
	}
	for _, ki := range h.KeysetInfo().GetKeyInfo() {
		if ki.GetKeyId() == keyID {
			return ki, nil
		}
	}
	return nil, fmt.Errorf("key ID %d not found", keyID)
}

// KeyInfo helper struct
type KeyInfo struct {
	KeyID    uint32
	Status   tinkpb.KeyStatusType
	Metadata *tinkrotatev1.KeyMetadata
}

// CheckConsistency verifies state between KeysetHandle and KeyRotationMetadata.
func CheckConsistency(handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata) []error {
	var inconsistencies []error
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if handle == nil {
		inconsistencies = append(inconsistencies, errors.New("keyset handle is nil"))
		return inconsistencies
	}
	ksInfo := handle.KeysetInfo()

	if metadata == nil {
		if len(ksInfo.GetKeyInfo()) > 0 {
			inconsistencies = append(inconsistencies, errors.New("metadata is nil, but keyset handle contains keys"))
		}
		return inconsistencies
	}

	if metadata.RotationPolicy == nil && len(ksInfo.GetKeyInfo()) > 0 {
		inconsistencies = append(inconsistencies, errors.New("metadata.RotationPolicy is nil"))
	}
	if metadata.KeyMetadata == nil {
		metadata.KeyMetadata = make(map[uint32]*tinkrotatev1.KeyMetadata)
	}

	tinkKeyIDs := make(map[uint32]*tinkpb.KeysetInfo_KeyInfo)
	for _, ki := range ksInfo.GetKeyInfo() {
		tinkKeyIDs[ki.GetKeyId()] = ki
	}

	metadataKeyIDs := make(map[uint32]*tinkrotatev1.KeyMetadata)
	for kID, meta := range metadata.KeyMetadata {
		if meta == nil {
			continue
		}
		metadataKeyIDs[kID] = meta
	}

	for kID := range tinkKeyIDs {
		if _, exists := metadataKeyIDs[kID]; !exists {
			inconsistencies = append(inconsistencies, fmt.Errorf("key ID %d missing from metadata", kID))
		}
	}

	for kID := range metadataKeyIDs {
		if _, exists := tinkKeyIDs[kID]; !exists {
			inconsistencies = append(inconsistencies, fmt.Errorf("metadata key ID %d missing from keyset", kID))
		}
	}

	tinkPrimaryID := ksInfo.GetPrimaryKeyId()
	var metadataPrimaryID uint32
	primaryCount := 0

	for kID, meta := range metadataKeyIDs {
		if _, exists := tinkKeyIDs[kID]; !exists {
			continue
		}
		if meta.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			metadataPrimaryID = kID
			primaryCount++
		}
	}

	if tinkPrimaryID != 0 {
		if primaryCount == 0 {
			inconsistencies = append(inconsistencies, fmt.Errorf("keyset primary %d not marked PRIMARY in metadata", tinkPrimaryID))
		} else if primaryCount > 1 {
			inconsistencies = append(inconsistencies, fmt.Errorf("multiple keys marked PRIMARY in metadata"))
		} else if metadataPrimaryID != tinkPrimaryID {
			inconsistencies = append(inconsistencies, fmt.Errorf("keyset primary %d mismatch metadata primary %d", tinkPrimaryID, metadataPrimaryID))
		}
	}

	for kID, tinkInfo := range tinkKeyIDs {
		meta, exists := metadataKeyIDs[kID]
		if !exists {
			continue
		}
		tinkStatus := tinkInfo.GetStatus()
		metaState := meta.State

		switch metaState {
		case tinkrotatev1.KeyState_KEY_STATE_PENDING, tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT, tinkrotatev1.KeyState_KEY_STATE_PRIMARY:
			if tinkStatus != tinkpb.KeyStatusType_ENABLED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key %d state %s but status %s", kID, metaState, tinkStatus))
			}
		case tinkrotatev1.KeyState_KEY_STATE_DISABLED:
			if tinkStatus != tinkpb.KeyStatusType_DISABLED && tinkStatus != tinkpb.KeyStatusType_DESTROYED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key %d state DISABLED but status %s", kID, tinkStatus))
			}
		}

		switch tinkStatus {
		case tinkpb.KeyStatusType_ENABLED:
			if metaState == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
				inconsistencies = append(inconsistencies, fmt.Errorf("key %d status ENABLED but state DISABLED", kID))
			}
		case tinkpb.KeyStatusType_UNKNOWN_STATUS:
			logger.Warn("Key found with UNKNOWN_STATUS", "keyID", kID)
		}
	}

	return inconsistencies
}
