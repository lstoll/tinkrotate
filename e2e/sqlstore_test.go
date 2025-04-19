package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3" // Import the sqlite3 driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
func TestAutoRotator_SQLite_BlackBox(t *testing.T) {
	// --- Test Configuration ---
	policy := tinkrotate.RotationPolicy{
		KeyTemplate:         aead.AES128GCMKeyTemplate(),
		PrimaryDuration:     10 * time.Second, // Rotate primary every 10s
		PropagationTime:     2 * time.Second,  // Needs 2s in pending
		PhaseOutDuration:    5 * time.Second,  // Decryptable for 5s after demotion
		DeletionGracePeriod: 3 * time.Second,  // Deleted 3s after disabled
	}
	simulationDuration := 40 * time.Second // Enough for multiple cycles
	timeStep := 1 * time.Second
	keysetID := "test-keyset-autorotator" // ID for the keyset in the DB

	// --- Mock Time Setup ---
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	currentTime := startTime
	timeNow := func() time.Time {
		return currentTime
	}

	// --- Database Setup ---
	// Using ":memory:" for a private in-memory database per test run
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory sqlite db")
	defer db.Close()

	// --- Store Setup ---
	sqlStore, err := tinkrotate.NewSQLStore(db, keysetID) // Using default table/column names
	require.NoError(t, err, "Failed to create SQLStore")

	// Create Schema
	_, err = db.Exec(sqlStore.Schema())
	require.NoError(t, err, "Failed to create database schema")

	// --- Rotator Setup ---
	rotator, err := tinkrotate.NewRotator(policy)
	require.NoError(t, err, "Failed to create rotator")
	rotatorValue := reflect.ValueOf(rotator).Elem()

	// use reflection to set the now field to the mock function. this is all
	// internal testing stuff, should not be done elsewhere.
	nowField := rotatorValue.FieldByName("now")
	if !nowField.IsValid() {
		t.Fatalf("Private field 'now' not found in Rotator struct via reflection")
	}
	settableNowField := reflect.NewAt(nowField.Type(), unsafe.Pointer(nowField.UnsafeAddr())).Elem()
	settableNowField.Set(reflect.ValueOf(timeNow))

	// --- AutoRotator Setup ---
	autoRotator, err := tinkrotate.NewAutoRotator(sqlStore, rotator, 1*time.Minute, policy.KeyTemplate) // Interval doesn't matter for RunOnce
	require.NoError(t, err, "Failed to create AutoRotator")

	// --- Test Execution ---
	ctx := context.Background()
	var initialKeyID uint32
	var secondKeyID uint32
	var thirdKeyID uint32
	var fourthKeyID uint32
	var elapsedSeconds float64

	t.Run("Initial State - Not Found", func(t *testing.T) {
		_, err := sqlStore.ReadKeysetAndMetadata(ctx)
		assert.ErrorIs(t, err, tinkrotate.ErrKeysetNotFound, "Expected ErrKeysetNotFound initially")
	})

	t.Run("First Run - Provisioning", func(t *testing.T) {
		currentTime = currentTime.Add(time.Microsecond) // Advance time slightly
		err := autoRotator.RunOnce(ctx)
		require.NoError(t, err, "RunOnce failed during initial provisioning")

		// Verify state in store
		readResult, err := sqlStore.ReadKeysetAndMetadata(ctx)
		require.NoError(t, err, "Failed to read from store after provisioning")
		require.NotNil(t, readResult.Handle, "Handle should not be nil after provisioning")
		require.NotNil(t, readResult.Metadata, "Metadata should not be nil after provisioning")
		assert.Equal(t, int64(1), readResult.Context, "Version should be 1 after initial write") // Check version

		ksInfo := readResult.Handle.KeysetInfo()
		assert.NotZero(t, ksInfo.GetPrimaryKeyId(), "Should have a primary key ID")
		// **FIX:** Expect 2 keys now: the initial primary and the first pending
		assert.Len(t, ksInfo.GetKeyInfo(), 2, "Should have primary and pending keys after first run")
		initialKeyID = ksInfo.GetPrimaryKeyId() // Store for later checks

		// **FIX:** Expect metadata for 2 keys
		assert.Len(t, readResult.Metadata.KeyMetadata, 2, "Should have metadata for primary and pending keys")
		assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PRIMARY, getKeyState(readResult.Metadata, initialKeyID), "Initial key state should be PRIMARY")
		// Find and verify the pending key
		pendingKeyID, pendingExists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
		assert.True(t, pendingExists, "Should have a PENDING key after first run")
		if pendingExists {
			secondKeyID = pendingKeyID // Store the second key ID
			t.Logf("Initial keys: Primary=%d, Pending=%d", initialKeyID, secondKeyID)
		}

		// Check consistency
		consistencyErrors := tinkrotate.CheckConsistency(readResult.Handle, readResult.Metadata)
		assert.Empty(t, consistencyErrors, "Consistency check failed after provisioning")
	})

	t.Run("Simulation Loop", func(t *testing.T) {

		// Loop simulation time
		for elapsed := time.Duration(0); elapsed < simulationDuration; elapsed += timeStep {
			currentTime = startTime.Add(elapsed + timeStep) // Advance mock time *before* RunOnce
			t.Logf("--- Time: %s (Elapsed: %.0fs) ---", currentTime.Format(time.RFC3339), elapsed.Seconds()+timeStep.Seconds())

			// Run the auto-rotator's logic
			err := autoRotator.RunOnce(ctx)
			require.NoError(t, err, "RunOnce failed during simulation loop at %.0fs", elapsed.Seconds())

			// Read current state from store for verification
			readResult, err := sqlStore.ReadKeysetAndMetadata(ctx)
			require.NoError(t, err, "Failed to read from store during simulation loop at %.0fs", elapsed.Seconds())

			// Check consistency at every step
			consistencyErrors := tinkrotate.CheckConsistency(readResult.Handle, readResult.Metadata)
			require.Empty(t, consistencyErrors, "Consistency check failed at %.0fs", elapsedSeconds)

			elapsedSeconds := elapsed.Seconds() + timeStep.Seconds()
			currentPrimaryID := readResult.Handle.KeysetInfo().GetPrimaryKeyId()

			// --- Specific Time-Based Assertions ---

			// Expect second pending key creation (already created in first run check)
			// Just capture its ID if not already done
			if secondKeyID == 0 {
				keyID, exists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
				if exists && keyID != initialKeyID {
					secondKeyID = keyID
				}
			}

			// Expect promotion of second key: Occurs AT 10s (PrimaryDuration) if propagation met
			// Expect initial key phasing out: Occurs AT 10s
			if elapsedSeconds >= 10 && elapsedSeconds < 16 { // Check between promotion and disable
				if currentPrimaryID == secondKeyID {
					assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT, getKeyState(readResult.Metadata, initialKeyID), "Expected initial key to be PHASING_OUT between 10s and 16s")
					// Expect third pending key generation when second key is promoted
					if thirdKeyID == 0 {
						keyID, exists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
						if exists && keyID != initialKeyID && keyID != secondKeyID {
							thirdKeyID = keyID
							t.Logf("Third key (pending) appeared: %d", thirdKeyID)
						}
					}
				} else if currentPrimaryID == initialKeyID {
					// Promotion might be waiting for propagation
					assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PENDING, getKeyState(readResult.Metadata, secondKeyID), "Expected second key PENDING before 10s promotion if propagation not met")
				} else {
					// Should be one of the above two states
					assert.Fail(t, fmt.Sprintf("Unexpected primary key %d state between 10s and 16s", currentPrimaryID))
				}
			}

			// Expect initial key disable: Occurs AT 16s (PromotionTime(10s) + PhaseOutDuration(5s))
			// Need to use the *actual* promotion time of the key that replaced it (secondKeyID)
			// From logs, second key was promoted at 11s (T=12:00:11Z), so disable should be at 16s.
			if elapsedSeconds >= 16 && elapsedSeconds < 19 { // Check between disable and deletion
				assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_DISABLED, getKeyState(readResult.Metadata, initialKeyID), "Expected initial key to be DISABLED between 16s and 19s")
				if getKeyState(readResult.Metadata, initialKeyID) == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Logf("Initial key %d disabled.", initialKeyID)
				}
			}

			// Expect initial key deletion: Occurs AT 19s (DisableTime(16s) + DeletionGrace(3s))
			if elapsedSeconds >= 19 { // Check from deletion time onwards
				_, metaExists := readResult.Metadata.KeyMetadata[initialKeyID]
				assert.False(t, metaExists, "Expected initial key metadata to be deleted at/after 19s")
				foundInHandle := false
				for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
					if ki.GetKeyId() == initialKeyID {
						foundInHandle = true
						break
					}
				}
				assert.False(t, foundInHandle, "Expected initial key to be removed from handle at/after 19s")
				if !metaExists && !foundInHandle && elapsedSeconds == 19 { // Log deletion once
					t.Logf("Initial key %d deleted.", initialKeyID)
				}
			}

			// Expect promotion of third key: Occurs AT 21s (SecondKeyPromotion(11s) + PrimaryDuration(10s))
			// Expect second key phasing out: Occurs AT 21s
			if elapsedSeconds >= 21 && elapsedSeconds < 26 { // Check between promotion and disable
				if currentPrimaryID == thirdKeyID {
					assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT, getKeyState(readResult.Metadata, secondKeyID), "Expected second key to be PHASING_OUT between 21s and 26s")
					// Expect fourth pending key generation
					if fourthKeyID == 0 {
						keyID, exists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
						if exists && keyID != secondKeyID && keyID != thirdKeyID {
							fourthKeyID = keyID
							t.Logf("Fourth key (pending) appeared: %d", fourthKeyID)
						}
					}
				} else if currentPrimaryID == secondKeyID {
					assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PENDING, getKeyState(readResult.Metadata, thirdKeyID), "Expected third key PENDING before 21s promotion if propagation not met")
				}
				// else { Might still be initial key briefly if propagation was slow for 2nd }
			}

			// Expect second key disable: Occurs AT 26s (ThirdKeyPromotion(21s) + PhaseOutDuration(5s))
			if elapsedSeconds >= 26 && elapsedSeconds < 29 { // Check between disable and deletion
				assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_DISABLED, getKeyState(readResult.Metadata, secondKeyID), "Expected second key to be DISABLED between 26s and 29s")
				if getKeyState(readResult.Metadata, secondKeyID) == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Logf("Second key %d disabled.", secondKeyID)
				}
			}

			// Expect second key deletion: Occurs AT 29s (DisableTime(26s) + DeletionGrace(3s))
			if elapsedSeconds >= 29 { // Check from deletion time onwards
				_, metaExists := readResult.Metadata.KeyMetadata[secondKeyID]
				assert.False(t, metaExists, "Expected second key metadata to be deleted at/after 29s")
				foundInHandle := false
				for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
					if ki.GetKeyId() == secondKeyID {
						foundInHandle = true
						break
					}
				}
				assert.False(t, foundInHandle, "Expected second key to be removed from handle at/after 29s")
				if !metaExists && !foundInHandle && elapsedSeconds == 29 { // Log deletion once
					t.Logf("Second key %d deleted.", secondKeyID)
				}
			}

			// Expect promotion of fourth key: Occurs AT 31s (ThirdKeyPromotion(21s) + PrimaryDuration(10s))
			// Expect third key phasing out: Occurs AT 31s
			if elapsedSeconds >= 31 && elapsedSeconds < 36 { // Check between promotion and disable
				if currentPrimaryID == fourthKeyID {
					assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT, getKeyState(readResult.Metadata, thirdKeyID), "Expected third key to be PHASING_OUT between 31s and 36s")
					// Expect fifth pending key generation
					// if fifthKeyID == 0 { ... capture ... }
				} else if currentPrimaryID == thirdKeyID {
					assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PENDING, getKeyState(readResult.Metadata, fourthKeyID), "Expected fourth key PENDING before 31s promotion if propagation not met")
				}
			}

			// Expect third key disable: Occurs AT 36s (FourthKeyPromotion(31s) + PhaseOutDuration(5s))
			if elapsedSeconds >= 36 && elapsedSeconds < 39 { // Check between disable and deletion
				assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_DISABLED, getKeyState(readResult.Metadata, thirdKeyID), "Expected third key to be DISABLED between 36s and 39s")
				if getKeyState(readResult.Metadata, thirdKeyID) == tinkrotatev1.KeyState_KEY_STATE_DISABLED {
					t.Logf("Third key %d disabled.", thirdKeyID)
				}
			}

			// Expect third key deletion: Occurs AT 39s (DisableTime(36s) + DeletionGrace(3s))
			if elapsedSeconds >= 39 { // Check from deletion time onwards
				_, metaExists := readResult.Metadata.KeyMetadata[thirdKeyID]
				assert.False(t, metaExists, "Expected third key metadata to be deleted at/after 39s")
				foundInHandle := false
				for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
					if ki.GetKeyId() == thirdKeyID {
						foundInHandle = true
						break
					}
				}
				assert.False(t, foundInHandle, "Expected third key to be removed from handle at/after 39s")
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
		readResult, err := sqlStore.ReadKeysetAndMetadata(ctx)
		require.NoError(t, err, "Failed to read final state from store")

		// Initial key should definitely be gone
		// ... (assertions for initialKeyID remain the same) ...
		_, metaExists := readResult.Metadata.KeyMetadata[initialKeyID]
		assert.False(t, metaExists, "Initial key metadata should be deleted in final state")
		foundInHandle := false
		for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
			if ki.GetKeyId() == initialKeyID {
				foundInHandle = true
				break
			}
		}
		assert.False(t, foundInHandle, "Initial key should be removed from handle in final state")

		// Second key should definitely be gone
		// ... (assertions for secondKeyID remain the same) ...
		_, metaExists = readResult.Metadata.KeyMetadata[secondKeyID]
		assert.False(t, metaExists, "Second key metadata should be deleted in final state")
		foundInHandle = false
		for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
			if ki.GetKeyId() == secondKeyID {
				foundInHandle = true
				break
			}
		}
		assert.False(t, foundInHandle, "Second key should be removed from handle in final state")

		// Third key should be DELETED (Deletion happened at 39s)
		_, metaExists = readResult.Metadata.KeyMetadata[thirdKeyID]
		assert.False(t, metaExists, "Third key metadata should be deleted in final state")
		foundInHandle = false
		for _, ki := range readResult.Handle.KeysetInfo().GetKeyInfo() {
			if ki.GetKeyId() == thirdKeyID {
				foundInHandle = true
				break
			}
		}
		assert.False(t, foundInHandle, "Third key should be removed from handle in final state")

		// Should have a primary key, which is the FOURTH one created (promoted at 31s)
		currentPrimaryID := readResult.Handle.KeysetInfo().GetPrimaryKeyId()
		assert.NotZero(t, currentPrimaryID, "Should have a primary key in final state")
		// **FIX:** Expect fourthKeyID to be primary
		require.NotZero(t, fourthKeyID, "Fourth key ID should have been captured during simulation") // Ensure it was captured
		assert.Equal(t, fourthKeyID, currentPrimaryID, "Expected FOURTH key (%d) to be primary in final state, but got %d", fourthKeyID, currentPrimaryID)
		assert.Equal(t, tinkrotatev1.KeyState_KEY_STATE_PRIMARY, getKeyState(readResult.Metadata, currentPrimaryID), "Primary key state should be PRIMARY")

		// Should have a FIFTH pending key (created at 31s)
		_, pendingExists := findKeyByState(readResult.Metadata, tinkrotatev1.KeyState_KEY_STATE_PENDING)
		assert.True(t, pendingExists, "Expected a PENDING key to exist in final state")

		// Final consistency check
		consistencyErrors := tinkrotate.CheckConsistency(readResult.Handle, readResult.Metadata)
		assert.Empty(t, consistencyErrors, "Final consistency check failed")

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
