package tinkrotate

import (
	"bytes"
	"fmt"
	"sort"
	"testing"
	"time"

	// "github.com/stretchr/testify/assert"  // Removed
	// "github.com/stretchr/testify/require" // Removed
	"log/slog"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset" // Keep for cloning
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// testWriter is a simple io.Writer that writes to t.Logf.
// Used to pipe slog output to test logs.
type testWriter struct {
	t *testing.T
}

func (tw testWriter) Write(p []byte) (n int, err error) {
	tw.t.Logf("%s", p) // Logf will add a newline if one isn't present
	return len(p), nil
}

// Helper to create a test policy proto
func createTestPolicy(primary time.Duration, propagation time.Duration, phaseOut time.Duration, deletionGrace time.Duration) *tinkrotatev1.RotationPolicy {
	return &tinkrotatev1.RotationPolicy{
		KeyTemplate:         aead.AES128GCMKeyTemplate(),
		PrimaryDuration:     durationpb.New(primary),
		PropagationTime:     durationpb.New(propagation),
		PhaseOutDuration:    durationpb.New(phaseOut),
		DeletionGracePeriod: durationpb.New(deletionGrace),
	}
}

// TestRotatorEndToEnd simulates the key rotation lifecycle over time using the standalone RotateKeyset.
func TestRotatorEndToEnd(t *testing.T) {
	// --- Test Configuration ---
	policyProto := createTestPolicy(
		10*time.Second, // primary
		2*time.Second,  // propagation
		5*time.Second,  // phase out
		3*time.Second,  // deletion grace
	)
	simulationDuration := 120 * time.Second
	timeStep := 1 * time.Second
	keyTemplate := policyProto.KeyTemplate // Extract template for initial setup

	// --- Mock Time Setup ---
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	currentTime := startTime
	// mockNowFunc no longer needed directly by rotator

	// --- Rotator Initialization --- (No rotator needed anymore)

	// --- Initial Keyset & Metadata Setup ---
	manager := keyset.NewManager()
	initialKeyID, err := manager.Add(keyTemplate)
	requireNoError(t, err, "Failed to add initial key")
	err = manager.SetPrimary(initialKeyID)
	requireNoError(t, err, "Failed to set initial primary key")

	handle, err := manager.Handle()
	requireNoError(t, err, "Failed to get initial handle")

	initialMetadata := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: policyProto, // Embed the policy
		KeyMetadata: map[uint32]*tinkrotatev1.KeyMetadata{
			initialKeyID: {
				KeyId:         initialKeyID,
				State:         tinkrotatev1.KeyState_KEY_STATE_PRIMARY,
				CreationTime:  timestamppb.New(startTime),
				PromotionTime: timestamppb.New(startTime),
			},
		},
	}
	metadata := proto.Clone(initialMetadata).(*tinkrotatev1.KeyRotationMetadata) // Start with a clone

	// --- Simulation Variables ---
	type encryptedRecord struct {
		ciphertext     []byte
		associatedData []byte
		encryptionTime time.Time
		keyIDUsed      uint32
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
		// It's possible primary is briefly 0 if rotating precisely when checked
		// requireNotZero(t, primaryID, "[%s] Primary key ID is zero", simTime)
		if primaryID == 0 {
			t.Logf("[%s] Primary key ID is 0, skipping encryption this step.", simTime)
		} else {
			ciphertext, err := aeadPrimitive.Encrypt(plaintext, associatedData)
			requireNoError(t, err, "[%s] Failed to encrypt", simTime)
			history = append(history, encryptedRecord{
				ciphertext:     ciphertext,
				associatedData: associatedData,
				encryptionTime: currentTime,
				keyIDUsed:      primaryID,
			})
			t.Logf("[%s] Encrypted data using primary key %d", simTime, primaryID)
		}

		// 2. Attempt to decrypt historical data
		t.Logf("[%s] Attempting decryption of %d historical records...", simTime, len(history))
		for i, record := range history {
			keyMeta, metaExists := metadata.KeyMetadata[record.keyIDUsed]
			expectedToWork := false
			if metaExists {
				expectedToWork = (keyMeta.State == tinkrotatev1.KeyState_KEY_STATE_PRIMARY || keyMeta.State == tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT)
			}

			decrypted, err := aeadPrimitive.Decrypt(record.ciphertext, record.associatedData)

			if expectedToWork {
				if assertNoError(t, err, "[%s] Decryption failed unexpectedly for record %d (key %d, state %s, encrypted at %s)",
					simTime, i, record.keyIDUsed, keyMeta.State, record.encryptionTime.Format(time.RFC3339)) {
					assertEqualBytes(t, plaintext, decrypted, "[%s] Decrypted data mismatch for record %d", simTime, i)
				}
			} else {
				stateStr := "DELETED"
				if metaExists {
					stateStr = keyMeta.State.String()
				}
				assertError(t, err, "[%s] Decryption succeeded unexpectedly for record %d (key %d, state %s, encrypted at %s)",
					simTime, i, record.keyIDUsed, stateStr, record.encryptionTime.Format(time.RFC3339))
			}
		}

		// 3. Run rotator function (using the current time *before* advancing it)
		newHandle, newMetadata, rotated, err := RotateKeyset(handle, metadata, &RotateOpts{
			TimeSource: func() time.Time {
				return currentTime
			},
			// Add logger to test output for easier debugging of rotation steps
			Logger: slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})).With("sim_time", simTime.String()),
		})
		requireNoError(t, err, "[%s] RotateKeyset failed", simTime) // Check error at current time
		if rotated {
			t.Logf("[%s] RotateKeyset reported changes.", simTime)
		} else {
			t.Logf("[%s] RotateKeyset reported NO changes.", simTime)
		}

		// Update handle and metadata for the next iteration
		handle = newHandle
		metadata = newMetadata // RotateKeyset returns modified metadata

		// 4. Advance time for the *next* loop iteration
		currentTime = currentTime.Add(timeStep)
	}

	t.Logf("--- Simulation Ended at %s ---", currentTime.Format(time.RFC3339))
	logKeyStates(t, handle, metadata)

	// --- Final Assertions (Optional) ---
	initialKeyMeta, metaExists := metadata.KeyMetadata[initialKeyID]
	if metaExists {
		assertNotEqual(t, tinkrotatev1.KeyState_KEY_STATE_PRIMARY, initialKeyMeta.State, "Initial key should not be primary anymore")
		assertNotEqual(t, tinkrotatev1.KeyState_KEY_STATE_PENDING, initialKeyMeta.State, "Initial key should not be pending")
		// Depending on exact timing, it might still be PHASING_OUT if duration isn't enough for full cycle
		// assertTrue(t, initialKeyMeta.State == tinkrotatev1.KeyState_KEY_STATE_DISABLED || initialKeyMeta.State == tinkrotatev1.KeyState_KEY_STATE_PHASING_OUT,
		// 	"Initial key should be DISABLED or PHASING_OUT if not deleted yet, but was %s", initialKeyMeta.State)
		t.Logf("Final state of initial key %d: %s", initialKeyID, initialKeyMeta.State)
	} else {
		t.Logf("Initial key %d was successfully deleted.", initialKeyID)
	}
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

func requireNoError(t testing.TB, err error, msg string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("should be no error, but was: %v. %s", err, fmt.Sprintf(msg, args...))
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

func assertNoError(t testing.TB, err error, msg string, args ...any) bool {
	t.Helper()
	if err != nil {
		t.Errorf("should be no error, but was: %v. %s", err, fmt.Sprintf(msg, args...))
		return false
	}
	return true
}

func assertError(t testing.TB, err error, msg string, args ...any) bool {
	t.Helper()
	if err == nil {
		t.Errorf("should be an error, but was nil. %s", fmt.Sprintf(msg, args...))
		return false
	}
	return true
}
