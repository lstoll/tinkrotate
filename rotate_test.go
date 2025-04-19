package tinkrotate

import (
	"bytes"
	"fmt"
	"sort"
	"testing"
	"time"

	// "github.com/stretchr/testify/assert"  // Removed
	// "github.com/stretchr/testify/require" // Removed
	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset" // Keep for cloning
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestRotatorEndToEnd simulates the key rotation lifecycle over time.
func TestRotatorEndToEnd(t *testing.T) {
	// --- Test Configuration ---
	policy := RotationPolicy{
		KeyTemplate:         aead.AES128GCMKeyTemplate(), // Fast AEAD template
		PrimaryDuration:     10 * time.Second,            // Keep primary for 10s
		PropagationTime:     2 * time.Second,             // Must be pending for 2s before promotion
		PhaseOutDuration:    5 * time.Second,             // Decryptable for 5s after replaced
		DeletionGracePeriod: 3 * time.Second,             // Wait 3s after disable before delete
	}
	simulationDuration := 120 * time.Second // Enough time for >1 full cycle
	timeStep := 1 * time.Second

	// --- Mock Time Setup ---
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	currentTime := startTime
	mockNowFunc := func() time.Time {
		return currentTime
	}

	// --- Rotator Initialization ---
	rotator, err := NewRotator(policy)
	requireNoError(t, err, "Failed to create rotator")
	rotator.now = mockNowFunc // Inject mock time source

	// --- Initial Keyset & Metadata Setup ---
	manager := keyset.NewManager()
	initialKeyID, err := manager.Add(policy.KeyTemplate)
	requireNoError(t, err, "Failed to add initial key")
	err = manager.SetPrimary(initialKeyID)
	requireNoError(t, err, "Failed to set initial primary key")

	handle, err := manager.Handle()
	requireNoError(t, err, "Failed to get initial handle")

	initialMetadata := &tinkrotatev1.KeyRotationMetadata{
		KeyMetadata: map[uint32]*tinkrotatev1.KeyMetadata{
			initialKeyID: {
				KeyId:         initialKeyID,
				State:         tinkrotatev1.KeyState_KEY_STATE_PRIMARY,
				CreationTime:  timestamppb.New(startTime), // Created now
				PromotionTime: timestamppb.New(startTime), // Promoted now
			},
		},
	}
	metadata := proto.Clone(initialMetadata).(*tinkrotatev1.KeyRotationMetadata) // Clone for safety

	// --- Simulation Variables ---
	type encryptedRecord struct {
		ciphertext     []byte
		associatedData []byte
		encryptionTime time.Time
		keyIDUsed      uint32 // Key ID that *should* have been used (primary at encryptionTime)
	}
	history := []encryptedRecord{}
	plaintext := []byte("Super secret data")
	associatedData := []byte("associated data")

	// --- Simulation Loop ---
	t.Logf("Starting simulation at %s", currentTime.Format(time.RFC3339))
	for simTime := time.Duration(0); simTime < simulationDuration; simTime += timeStep {
		t.Logf("--- Time: %s (Simulated +%s) ---", currentTime.Format(time.RFC3339), simTime)

		// Log current key states
		logKeyStates(t, handle, metadata)

		// 1. Encrypt with current primary key
		aeadPrimitive, err := aead.New(handle)
		requireNoError(t, err, "[%s] Failed to get AEAD primitive", simTime)

		primaryID := handle.KeysetInfo().GetPrimaryKeyId()
		requireNotZero(t, primaryID, "[%s] Primary key ID is zero", simTime)

		ciphertext, err := aeadPrimitive.Encrypt(plaintext, associatedData)
		requireNoError(t, err, "[%s] Failed to encrypt", simTime)
		history = append(history, encryptedRecord{
			ciphertext:     ciphertext,
			associatedData: associatedData,
			encryptionTime: currentTime,
			keyIDUsed:      primaryID,
		})
		t.Logf("[%s] Encrypted data using primary key %d", simTime, primaryID)

		// 2. Attempt to decrypt historical data
		t.Logf("[%s] Attempting decryption of %d historical records...", simTime, len(history))
		for i, record := range history {
			keyMeta, metaExists := metadata.KeyMetadata[record.keyIDUsed]
			expectedToWork := false
			if metaExists {
				// Decryption should work if the key used is currently PRIMARY or PHASING_OUT
				expectedToWork = (keyMeta.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY || keyMeta.State == tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT)
			} // If !metaExists, key was deleted, expectedToWork remains false

			decrypted, err := aeadPrimitive.Decrypt(record.ciphertext, record.associatedData)

			if expectedToWork {
				// Expect decryption to succeed
				if assertNoError(t, err, "[%s] Decryption failed unexpectedly for record %d (key %d, state %s, encrypted at %s)",
					simTime, i, record.keyIDUsed, keyMeta.State, record.encryptionTime.Format(time.RFC3339)) {
					assertEqualBytes(t, plaintext, decrypted, "[%s] Decrypted data mismatch for record %d", simTime, i)
					// t.Logf("[%s] Decryption SUCCESS (expected) for record %d (key %d, state %s)", simTime, i, record.keyIDUsed, keyMeta.State)
				}
			} else {
				// Expect decryption to fail (key is PENDING, DISABLED, or DELETED)
				stateStr := "DELETED"
				if metaExists {
					stateStr = keyMeta.State.String()
				}
				assertError(t, err, "[%s] Decryption succeeded unexpectedly for record %d (key %d, state %s, encrypted at %s)",
					simTime, i, record.keyIDUsed, stateStr, record.encryptionTime.Format(time.RFC3339))
				// t.Logf("[%s] Decryption FAILED (expected) for record %d (key %d, state %s)", simTime, i, record.keyIDUsed, stateStr)
			}
		}

		// 3. Advance time
		currentTime = currentTime.Add(timeStep)

		// 4. Run rotator
		newHandle, newMetadata, err := rotator.RotateKeyset(handle, metadata)
		requireNoError(t, err, "[%s] RotateKeyset failed", simTime+timeStep) // Check error at next logical time step

		// Update handle and metadata for the next iteration
		handle = newHandle
		metadata = newMetadata // RotateKeyset should return the same map instance, modified
	}

	t.Logf("--- Simulation Ended at %s ---", currentTime.Format(time.RFC3339))
	logKeyStates(t, handle, metadata)

	// --- Final Assertions (Optional) ---
	// Example: Check if the initial key eventually got deleted (or is at least DISABLED)
	initialKeyMeta, metaExists := metadata.KeyMetadata[initialKeyID]
	if metaExists {
		assertNotEqual(t, tinkrotatev1.KeyState_KEY_STATE_PRIMARY, initialKeyMeta.State, "Initial key should not be primary anymore")
		assertNotEqual(t, tinkrotatev1.KeyState_KEY_STATE_PENDING, initialKeyMeta.State, "Initial key should not be pending")
		assertTrue(t, initialKeyMeta.State == tinkrotatev1.KeyState_KEY_STATE_DISABLED || initialKeyMeta.State == tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT,
			"Initial key should be DISABLED or PHASING_OUT if not deleted yet, but was %s", initialKeyMeta.State)
	} else {
		t.Logf("Initial key %d was successfully deleted.", initialKeyID)
	}
	// Example: Check if there's a primary key
	assertNotZero(t, handle.KeysetInfo().GetPrimaryKeyId(), "There should be a primary key at the end")
}

// Helper function to log current key states
func logKeyStates(t *testing.T, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata) {
	t.Helper()
	if handle == nil || metadata == nil || metadata.KeyMetadata == nil {
		t.Logf("  Keyset/Metadata nil, cannot log states.")
		return
	}
	tinkInfo := handle.KeysetInfo()
	primaryID := tinkInfo.GetPrimaryKeyId()
	t.Logf("  Current Keyset State (Tink Primary: %d):", primaryID)

	// Sort keys for consistent logging
	keyIDs := make([]uint32, 0, len(metadata.KeyMetadata))
	for kID := range metadata.KeyMetadata {
		keyIDs = append(keyIDs, kID)
	}
	sort.Slice(keyIDs, func(i, j int) bool { return keyIDs[i] < keyIDs[j] })

	for _, keyID := range keyIDs {
		meta := metadata.KeyMetadata[keyID]
		statusStr := "UNKNOWN_IN_TINK"
		prefix := ""
		for _, ki := range tinkInfo.GetKeyInfo() {
			if ki.GetKeyId() == keyID {
				statusStr = ki.GetStatus().String()
				break
			}
		}
		if keyID == primaryID {
			prefix = "[PRIMARY] "
		}
		t.Logf("    %sKey %d: Metadata State=%s, Tink Status=%s (Created: %s, Promoted: %s, Disabled: %s, Deletion: %s)",
			prefix,
			keyID,
			meta.State,
			statusStr,
			formatTime(meta.CreationTime),
			formatTime(meta.PromotionTime),
			formatTime(meta.DisableTime),
			formatTime(meta.DeletionTime),
		)
	}
}

// Helper to format timestamps for logging
func formatTime(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "Never"
	}
	// Check for zero time just in case
	if ts.Seconds == 0 && ts.Nanos == 0 {
		return "Never"
	}
	return ts.AsTime().Format(time.RFC3339)
}

func assertNotZero[T ~int | ~float64 | ~uint32](t testing.TB, v T, msg string, args ...any) {
	t.Helper()
	if v == 0 {
		t.Fatalf("should be not zero, but was: %s", fmt.Sprintf(msg, args...))
	}
}

func assertTrue[T ~bool](t testing.TB, v T, msg string, args ...any) {
	t.Helper()
	if !v {
		t.Fatalf("should be true, but was: %s", fmt.Sprintf(msg, args...))
	}
}

func requireNoError(t testing.TB, err error, msg string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("should be no error, but was: %v. %s", err, fmt.Sprintf(msg, args...))
	}
}

func assertEqual[T comparable](t testing.TB, a, b T, msg string, args ...any) {
	t.Helper()
	if a != b {
		t.Fatalf("should be equal, but was: %v. %s", b, fmt.Sprintf(msg, args...))
	}
}

func assertEqualBytes(t testing.TB, a, b []byte, msg string, args ...any) {
	t.Helper()
	if !bytes.Equal(a, b) {
		t.Fatalf("should be equal, but was: %v. %s", b, fmt.Sprintf(msg, args...))
	}
}

func assertNotEqual[T comparable](t testing.TB, a, b T, msg string, args ...any) {
	t.Helper()
	if a == b {
		t.Fatalf("should be not equal, but was: %v. %s", b, fmt.Sprintf(msg, args...))
	}
}

func requireNotZero[T ~int | ~float64 | ~uint32](t testing.TB, v T, msg string, args ...any) {
	t.Helper()
	if v == 0 {
		t.Fatalf("should be not zero, but was: %s", fmt.Sprintf(msg, args...))
	}
}

func assertNoError(t testing.TB, err error, msg string, args ...any) bool {
	t.Helper()
	if err != nil {
		t.Fatalf("should be no error, but was: %v. %s", err, fmt.Sprintf(msg, args...))
	}
	return true
}

func assertError(t testing.TB, err error, msg string, args ...any) bool {
	t.Helper()
	if err == nil {
		t.Fatalf("should be an error, but was: %s", fmt.Sprintf(msg, args...))
	}
	return true
}
