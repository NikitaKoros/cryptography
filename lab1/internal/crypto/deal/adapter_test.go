package deal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func TestDESAdapterValidBlockSize(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	block := make([]byte, 16)
	roundKey := make([]byte, 8)
	rand.Read(block)
	rand.Read(roundKey)

	result, err := adapter.EncryptRound(block, roundKey)
	if err != nil {
		t.Fatalf("EncryptRound failed: %v", err)
	}

	if len(result) != 16 {
		t.Errorf("Expected result length 16, got %d", len(result))
	}

	if bytes.Equal(result, block) {
		t.Error("Expected encrypted result to be different from original block")
	}
}

func TestDESAdapterInvalidBlockSize(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	testCases := []struct {
		name      string
		blockSize int
		wantError bool
	}{
		{"Valid 16-byte block", 16, false},
		{"Invalid 15-byte block", 15, true},
		{"Invalid 17-byte block", 17, true},
		{"Invalid 8-byte block", 8, true},
		{"Invalid 24-byte block", 24, true},
		{"Invalid 32-byte block", 32, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block := make([]byte, tc.blockSize)
			roundKey := make([]byte, 8)
			rand.Read(block)
			rand.Read(roundKey)

			result, err := adapter.EncryptRound(block, roundKey)

			if (err != nil) != tc.wantError {
				t.Errorf("EncryptRound() error = %v, wantError %v", err, tc.wantError)
				return
			}

			if !tc.wantError && len(result) != tc.blockSize {
				t.Errorf("Expected result length %d, got %d", tc.blockSize, len(result))
			}
		})
	}
}

func TestDESAdapterConsistency(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	block := make([]byte, 16)
	roundKey := make([]byte, 8)
	rand.Read(block)
	rand.Read(roundKey)

	firstResult, err := adapter.EncryptRound(block, roundKey)
	if err != nil {
		t.Fatalf("First EncryptRound failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		result, err := adapter.EncryptRound(block, roundKey)
		if err != nil {
			t.Fatalf("EncryptRound iteration %d failed: %v", i, err)
		}

		if !bytes.Equal(result, firstResult) {
			t.Errorf("EncryptRound is not deterministic at iteration %d", i)
			t.Errorf("First: %x", firstResult)
			t.Errorf("Current: %x", result)
		}
	}
}

func TestDESAdapterDecryptRound(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	block := make([]byte, 16)
	roundKey := make([]byte, 8)
	rand.Read(block)
	rand.Read(roundKey)

	encrypted, err := adapter.EncryptRound(block, roundKey)
	if err != nil {
		t.Fatalf("EncryptRound failed: %v", err)
	}

	decrypted, err := adapter.DecryptRound(encrypted, roundKey)
	if err != nil {
		t.Fatalf("DecryptRound failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Error("DecryptRound did not return original block")
		t.Errorf("Original: %x", block)
		t.Errorf("Decrypted: %x", decrypted)
	}
}
