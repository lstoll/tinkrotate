package e2e

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"                     // Import the sqlite3 driver
	"google.golang.org/protobuf/types/known/durationpb" // Import durationpb

	// Added for cmp.Equal and cmp.Diff
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"

	// Import your local package and the generated protobuf package
	"github.com/lstoll/tinkrotate" // Adjust import path for keyrotation package
	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
)

// Helper function to get key metadata state or UNSPECIFIED if not found
func getKeyState(metadata *tinkrotatev1.KeyRotationMetadata, keyID uint32) tinkrotatev1.KeyState {
	if metadata == nil || metadata.KeyMetadata == nil {
		return tinkrotatev1.KeyState_KEY_STATE_UNSPECIFIED
	}
	meta, exists := metadata.KeyMetadata[keyID]
	if !exists || meta == nil {
		return tinkrotatev1.KeyState_KEY_STATE_UNSPECIFIED // Or a specific "NotFound" state if preferred
	}
	return meta.State
}

// Helper function to find a key ID by state
func findKeyByState(metadata *tinkrotatev1.KeyRotationMetadata, state tinkrotatev1.KeyState) (uint32, bool) {
	if metadata == nil || metadata.KeyMetadata == nil {
		return 0, false
	}
	for keyID, meta := range metadata.KeyMetadata {
		if meta != nil && meta.State == state {
			return keyID, true // Return first match
		}
	}
	return 0, false
}

// TestAutoRotator_SQLite_BlackBox tests the AutoRotator using SQLStore with SQLite.
func runStoreTest(t *testing.T, store tinkrotate.ManagedStore) {
	keysetName := "test-keyset-" + uuid.New().String()
	// --- Test Configuration ---
	policy := &tinkrotatev1.RotationPolicy{ // Use proto definition
		KeyTemplate:         aead.AES128GCMKeyTemplate(),      // Use the actual template proto
		PrimaryDuration:     durationpb.New(10 * time.Second), // Use durationpb.New
		PropagationTime:     durationpb.New(2 * time.Second),  // Use durationpb.New
		PhaseOutDuration:    durationpb.New(5 * time.Second),  // Use durationpb.New
		DeletionGracePeriod: durationpb.New(3 * time.Second),  // Use durationpb.New
	}
	simulationDuration := 40 * time.Second // Enough for multiple cycles
	timeStep := 1 * time.Second

	// --- Mock Time Setup ---
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	currentTime := startTime
	// timeNow := func() time.Time {
	// 	return currentTime
	// }

	// --- Rotator Setup ---
	autoRotator, err := tinkrotate.NewAutoRotator(store, 1*time.Minute, &tinkrotate.AutoRotatorOpts{
		TimeSource: func() time.Time {
			return currentTime
		},
		ProvisionPolicies: map[string]*tinkrotatev1.RotationPolicy{
			keysetName: policy,
		},
	}) // Create the Rotator instance using the proto policy
	if err != nil {
		t.Fatalf("Failed to create autoRotator: %v", err)
	}
	// rotatorValue := reflect.ValueOf(rotator).Elem()

	// use reflection to set the now field to the mock function. this is all
	// internal testing stuff, should not be done elsewhere.
	// nowField := rotatorValue.FieldByName("now")
	// if !nowField.IsValid() {
	// 	t.Fatalf("Private field 'now' not found in Rotator struct via reflection")
	// }
	// settableNowField := reflect.NewAt(nowField.Type(), unsafe.Pointer(nowField.UnsafeAddr())).Elem()
	// settableNowField.Set(reflect.ValueOf(timeNow))

	// --- AutoRotator Setup ---
	// Tell the rotator which keyset name we are testing explicitly
	// AutoRotator no longer takes a rotator directly.
	// Provisioning might be implicit or handled via a different option/method.
	// Removing the ProvisionKeysetNames option for now.
	// autoRotator, err := tinkrotate.NewAutoRotator(store, 1*time.Minute, &tinkrotate.AutoRotatorOpts{ /* ProvisionKeysetNames removed */ })
	// require.NoError(t, err, "Failed to create AutoRotator")

	// --- Test Execution ---
	ctx := context.Background()
	var initialKeyID uint32
	var secondKeyID uint32
	var thirdKeyID uint32
	var fourthKeyID uint32
	var elapsedSeconds float64

	t.Run("Initial State - Not Found", func(t *testing.T) {
		_, err := store.ReadKeysetAndMetadata(ctx, keysetName)
		if !errors.Is(err, tinkrotate.ErrKeysetNotFound) {
			t.Errorf("Expected ErrKeysetNotFound initially, got %v", err)
		}
	})

	seenContext := make(map[any]struct{})

	t.Run("First Run - Provisioning", func(t *testing.T) {
		currentTime = currentTime.Add(time.Microsecond) // Advance time slightly
		err := autoRotator.RunOnce(ctx)
		if err != nil {
			t.Fatalf("RunOnce failed during initial provisioning: %v", err)
		}

		// Verify state in store
		readResult, err := store.ReadKeysetAndMetadata(ctx, keysetName)
		seenContext[readResult.Context] = struct{}{}
		if err != nil {
			t.Fatalf("Failed to read from store after provisioning: %v", err)
		}
		if readResult.Handle == nil {
			t.Fatal("Handle should not be nil after provisioning")
		}
		if readResult.Metadata == nil {
			t.Fatal("Metadata should not be nil after provisioning")
		}
		if len(seenContext) != 1 {
			t.Errorf("Should be one version after initial write: got %d, want %d", len(seenContext), 1)
		} // Check version

		ksInfo := readResult.Handle.KeysetInfo()
		if ksInfo.GetPrimaryKeyId() == 0 {
			t.Error("Should have a primary key ID")
		}
		// **FIX:** Expect 2 keys now: the initial primary and the first pending
		if len(ksInfo.GetKeyInfo()) != 2 {
			t.Errorf("Should have primary and pending keys after first run: got len %d, want %d", len(ksInfo.GetKeyInfo()), 2)
		}
		initialKeyID = ksInfo.GetPrimaryKeyId() // Store for later checks

		// **FIX:** Expect metadata for 2 keys
		if len(readResult.Metadata.KeyMetadata) != 2 {
			t.Errorf("Should have metadata for primary and pending keys: got len %d, want %d", len(readResult.Metadata.KeyMetadata), 2)
		}
		if getKeyState(readResult.Metadata, initialKeyID) != tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			t.Errorf("Initial key state should be PRIMARY: got %v, want %v", getKeyState(readResult.Metadata, initialKeyID), tinkrotatev1.KeyState_KEY_STATE_PRIMARY)
		}
		// Find and verify the pending key
		pendingKeyID, pendingExists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
		if !pendingExists {
			t.Error("Should have a PENDING key after first run")
		}
		if pendingExists {
			secondKeyID = pendingKeyID // Store the second key ID
			t.Logf("Initial keys: Primary=%d, Pending=%d", initialKeyID, secondKeyID)
		}

		// Check consistency
		consistencyErrors := tinkrotate.CheckConsistency(readResult.Handle, readResult.Metadata)
		if len(consistencyErrors) != 0 {
			t.Errorf("Consistency check failed after provisioning: %v", consistencyErrors)
		}
	})

	t.Run("Simulation Loop", func(t *testing.T) {

		// Loop simulation time
		for elapsed := time.Duration(0); elapsed < simulationDuration; elapsed += timeStep {
			currentTime = startTime.Add(elapsed + timeStep) // Advance mock time *before* RunOnce
			t.Logf("--- Time: %s (Elapsed: %.0fs) ---", currentTime.Format(time.RFC3339), elapsed.Seconds()+timeStep.Seconds())

			// Run the auto-rotator's logic
			err := autoRotator.RunOnce(ctx)
			if err != nil {
				t.Fatalf("RunOnce failed during simulation loop at %.0fs: %v", elapsed.Seconds(), err)
			}

			// Read current state from store for verification
			readResult, err := store.ReadKeysetAndMetadata(ctx, keysetName)
			if err != nil {
				t.Fatalf("Failed to read from store during simulation loop at %.0fs: %v", elapsed.Seconds(), err)
			}

			// Check consistency at every step
			consistencyErrors := tinkrotate.CheckConsistency(readResult.Handle, readResult.Metadata)
			if len(consistencyErrors) != 0 {
				t.Fatalf("Consistency check failed at %.0fs: %v", elapsedSeconds, consistencyErrors)
			}

			elapsedSeconds := elapsed.Seconds() + timeStep.Seconds()
			currentPrimaryID := readResult.Handle.KeysetInfo().GetPrimaryKeyId()

			// --- Specific Time-Based Assertions ---

			// Expect second pending key creation (should happen on first iteration of this loop, T=1s)
			if secondKeyID == 0 {
				keyID, exists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
				if exists && keyID != initialKeyID {
					secondKeyID = keyID
					t.Logf("Second key (pending) appeared: %d", secondKeyID)
				}
			}

			// Expect promotion of second key: Occurs AT 10s (PrimaryDuration) if propagation met
			// Expect initial key phasing out: Occurs AT 10s
			if elapsedSeconds >= 10 && elapsedSeconds < 16 { // Check between promotion and disable
				switch currentPrimaryID {
				case secondKeyID:
					if getKeyState(readResult.Metadata, initialKeyID) != tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT {
						t.Errorf("Expected initial key to be PHASING_OUT between 10s and 16s: got %v", getKeyState(readResult.Metadata, initialKeyID))
					}
					// Expect third pending key generation when second key is promoted
					if thirdKeyID == 0 {
						keyID, exists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
						if exists && keyID != initialKeyID && keyID != secondKeyID {
							thirdKeyID = keyID
							t.Logf("Third key (pending) appeared: %d", thirdKeyID)
						}
					}
				case initialKeyID:
					// Promotion might be waiting for propagation
					if getKeyState(readResult.Metadata, secondKeyID) != tinkrotatev1.KeyState_KEY_STATE_PENDING {
						t.Errorf("Expected second key PENDING before 10s promotion if propagation not met: got %v", getKeyState(readResult.Metadata, secondKeyID))
					}
				default:
					// Should be one of the above two states
					t.Fatalf("Unexpected primary key %d state between 10s and 16s", currentPrimaryID)
				}
			}

			// Expect initial key disable: Occurs AT 16s (PromotionTime(10s) + PhaseOutDuration(5s))
			// Need to use the *actual* promotion time of the key that replaced it (secondKeyID)
			// From logs, second key was promoted at 11s (T=12:00:11Z), so disable should be at 16s.
			if elapsedSeconds >= 16 && elapsedSeconds < 19 { // Check between disable and deletion
				if getKeyState(readResult.Metadata, initialKeyID) != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Errorf("Expected initial key to be DISABLED between 16s and 19s: got %v", getKeyState(readResult.Metadata, initialKeyID))
				}
				if getKeyState(readResult.Metadata, initialKeyID) == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Logf("Initial key %d disabled.", initialKeyID)
				}
			}

			// Expect initial key deletion: Occurs AT 19s (DisableTime(16s) + DeletionGrace(3s))
			if elapsedSeconds >= 19 { // Check from deletion time onwards
				_, metaExists := readResult.Metadata.KeyMetadata[initialKeyID]
				if metaExists {
					t.Error("Expected initial key metadata to be deleted at/after 19s")
				}
				foundInHandle := false
				for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
					if ki.GetKeyId() == initialKeyID {
						foundInHandle = true
						break
					}
				}
				if foundInHandle {
					t.Error("Expected initial key to be removed from handle at/after 19s")
				}
				if !metaExists && !foundInHandle && elapsedSeconds == 19 { // Log deletion once
					t.Logf("Initial key %d deleted.", initialKeyID)
				}
			}

			// Expect promotion of third key: Occurs AT 21s (SecondKeyPromotion(11s) + PrimaryDuration(10s))
			// Expect second key phasing out: Occurs AT 21s
			if elapsedSeconds >= 21 && elapsedSeconds < 26 { // Check between promotion and disable
				if currentPrimaryID == thirdKeyID {
					if getKeyState(readResult.Metadata, secondKeyID) != tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT {
						t.Errorf("Expected second key to be PHASING_OUT between 21s and 26s: got %v", getKeyState(readResult.Metadata, secondKeyID))
					}
					// Expect fourth pending key generation
					if fourthKeyID == 0 {
						keyID, exists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
						if exists && keyID != secondKeyID && keyID != thirdKeyID {
							fourthKeyID = keyID
							t.Logf("Fourth key (pending) appeared: %d", fourthKeyID)
						}
					}
				} else if currentPrimaryID == secondKeyID {
					if getKeyState(readResult.Metadata, thirdKeyID) != tinkrotatev1.KeyState_KEY_STATE_PENDING {
						t.Errorf("Expected third key PENDING before 21s promotion if propagation not met: got %v", getKeyState(readResult.Metadata, thirdKeyID))
					}
				}
				// else { Might still be initial key briefly if propagation was slow for 2nd }
			}

			// Expect second key disable: Occurs AT 26s (ThirdKeyPromotion(21s) + PhaseOutDuration(5s))
			if elapsedSeconds >= 26 && elapsedSeconds < 29 { // Check between disable and deletion
				if getKeyState(readResult.Metadata, secondKeyID) != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Errorf("Expected second key to be DISABLED between 26s and 29s: got %v", getKeyState(readResult.Metadata, secondKeyID))
				}
				if getKeyState(readResult.Metadata, secondKeyID) == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Logf("Second key %d disabled.", secondKeyID)
				}
			}

			// Expect second key deletion: Occurs AT 29s (DisableTime(26s) + DeletionGrace(3s))
			if elapsedSeconds >= 29 { // Check from deletion time onwards
				_, metaExists := readResult.Metadata.KeyMetadata[secondKeyID]
				if metaExists {
					t.Error("Expected second key metadata to be deleted at/after 29s")
				}
				foundInHandle := false
				for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
					if ki.GetKeyId() == secondKeyID {
						foundInHandle = true
						break
					}
				}
				if foundInHandle {
					t.Error("Expected second key to be removed from handle at/after 29s")
				}
				if !metaExists && !foundInHandle && elapsedSeconds == 29 { // Log deletion once
					t.Logf("Second key %d deleted.", secondKeyID)
				}
			}

			// Expect promotion of fourth key: Occurs AT 31s (ThirdKeyPromotion(21s) + PrimaryDuration(10s))
			// Expect third key phasing out: Occurs AT 31s
			if elapsedSeconds >= 31 && elapsedSeconds < 36 { // Check between promotion and disable
				if currentPrimaryID == fourthKeyID {
					if getKeyState(readResult.Metadata, thirdKeyID) != tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT {
						t.Errorf("Expected third key to be PHASING_OUT between 31s and 36s: got %v", getKeyState(readResult.Metadata, thirdKeyID))
					}
					// Expect fifth pending key generation
					// if fifthKeyID == 0 { ... capture ... }
				} else if currentPrimaryID == thirdKeyID {
					if getKeyState(readResult.Metadata, fourthKeyID) != tinkrotatev1.KeyState_KEY_STATE_PENDING {
						t.Errorf("Expected fourth key PENDING before 31s promotion if propagation not met: got %v", getKeyState(readResult.Metadata, fourthKeyID))
					}
				}
			}

			// Expect third key disable: Occurs AT 36s (FourthKeyPromotion(31s) + PhaseOutDuration(5s))
			if elapsedSeconds >= 36 && elapsedSeconds < 39 { // Check between disable and deletion
				if getKeyState(readResult.Metadata, thirdKeyID) != tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Errorf("Expected third key to be DISABLED between 36s and 39s: got %v", getKeyState(readResult.Metadata, thirdKeyID))
				}
				if getKeyState(readResult.Metadata, thirdKeyID) == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Logf("Third key %d disabled.", thirdKeyID)
				}
			}

			// Expect third key deletion: Occurs AT 39s (DisableTime(36s) + DeletionGrace(3s))
			if elapsedSeconds >= 39 { // Check from deletion time onwards
				_, metaExists := readResult.Metadata.KeyMetadata[thirdKeyID]
				if metaExists {
					t.Error("Expected third key metadata to be deleted at/after 39s")
				}
				foundInHandle := false
				for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
					if ki.GetKeyId() == thirdKeyID {
						foundInHandle = true
						break
					}
				}
				if foundInHandle {
					t.Error("Expected third key to be removed from handle at/after 39s")
				}
				if !metaExists && !foundInHandle && elapsedSeconds == 39 { // Log deletion once
					t.Logf("Third key %d deleted.", thirdKeyID)
				}
			}

			// Log state summary
			logKeyStatesSummary(t, readResult.Handle, readResult.Metadata)
		} // End simulation loop
	})
	t.Run("Final State Verification", func(t *testing.T) {
		// Read final state (at end of simulation, currentTime = startTime + 40s)
		readResult, err := store.ReadKeysetAndMetadata(ctx, keysetName)
		if err != nil {
			t.Fatalf("Failed to read final state from store: %v", err)
		}

		// Initial key should definitely be gone
		// ... (assertions for initialKeyID remain the same) ...
		_, metaExists := readResult.Metadata.KeyMetadata[initialKeyID]
		if metaExists {
			t.Error("Initial key metadata should be deleted in final state")
		}
		foundInHandle := false
		for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
			if ki.GetKeyId() == initialKeyID {
				foundInHandle = true
				break
			}
		}
		if foundInHandle {
			t.Error("Initial key should be removed from handle in final state")
		}

		// Second key should definitely be gone
		// ... (assertions for secondKeyID remain the same) ...
		_, metaExists = readResult.Metadata.KeyMetadata[secondKeyID]
		if metaExists {
			t.Error("Second key metadata should be deleted in final state")
		}
		foundInHandle = false
		for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
			if ki.GetKeyId() == secondKeyID {
				foundInHandle = true
				break
			}
		}
		if foundInHandle {
			t.Error("Second key should be removed from handle in final state")
		}

		// Third key should be DELETED (Deletion happened at 39s)
		_, metaExists = readResult.Metadata.KeyMetadata[thirdKeyID]
		if metaExists {
			t.Error("Third key metadata should be deleted in final state")
		}
		foundInHandle = false
		for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
			if ki.GetKeyId() == thirdKeyID {
				foundInHandle = true
				break
			}
		}
		if foundInHandle {
			t.Error("Third key should be removed from handle in final state")
		}

		// Should have a primary key, which is the FOURTH one created (promoted at 31s)
		currentPrimaryID := readResult.Handle.KeysetInfo().GetPrimaryKeyId()
		if currentPrimaryID == 0 {
			t.Error("Should have a primary key in final state")
		}
		// **FIX:** Expect fourthKeyID to be primary
		if fourthKeyID == 0 {
			t.Fatal("Fourth key ID should have been captured during simulation")
		} // Ensure it was captured
		if fourthKeyID != currentPrimaryID {
			t.Errorf("Expected FOURTH key (%d) to be primary in final state, but got %d", fourthKeyID, currentPrimaryID)
		}
		if getKeyState(readResult.Metadata, currentPrimaryID) != tinkrotatev1.KeyState_KEY_STATE_PRIMARY {
			t.Errorf("Primary key state should be PRIMARY: got %v", getKeyState(readResult.Metadata, currentPrimaryID))
		}

		// Should have a FIFTH pending key (created at 31s)
		_, pendingExists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
		if !pendingExists {
			t.Error("Expected a PENDING key to exist in final state")
		}

		// Final consistency check
		consistencyErrors := tinkrotate.CheckConsistency(readResult.Handle, readResult.Metadata)
		if len(consistencyErrors) != 0 {
			t.Errorf("Final consistency check failed: %v", consistencyErrors)
		}

		t.Logf("--- Final State Summary ---")
		logKeyStatesSummary(t, readResult.Handle, readResult.Metadata)

	})

}

// Helper function to log current key states concisely
func logKeyStatesSummary(t *testing.T, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata) {
	t.Helper()
	if handle == nil || metadata == nil || metadata.KeyMetadata == nil {
		t.Logf("  Keyset/Metadata nil, cannot log states.")
		return
	}
	tinkInfo := handle.KeysetInfo()
	primaryID := tinkInfo.GetPrimaryKeyId()
	summary := fmt.Sprintf("  Keyset Summary (Primary: %d): ", primaryID)

	// Sort keys for consistent logging
	keyIDs := make([]uint32, 0, len(metadata.KeyMetadata))
	for kID := range metadata.KeyMetadata {
		keyIDs = append(keyIDs, kID)
	}
	sort.Slice(keyIDs, func(i, j int) bool { return keyIDs[i] < keyIDs[j] })

	for i, keyID := range keyIDs {
		meta := metadata.KeyMetadata[keyID]
		if i > 0 {
			summary += ", "
		}
		summary += fmt.Sprintf("Key %d (%s)", keyID, meta.State)
	}
	t.Log(summary)
}
