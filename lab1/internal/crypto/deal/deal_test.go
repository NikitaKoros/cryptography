package deal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func TestDEAL128(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	key := make([]byte, 16)
	block := make([]byte, 16)
	rand.Read(key)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	if len(encrypted) != 16 {
		t.Errorf("Expected encrypted block size 16, got %d", len(encrypted))
	}

	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Error("Decrypted block does not match original")
		t.Errorf("Original: %x", block)
		t.Errorf("Decrypted: %x", decrypted)
	}
}

func TestDEAL192(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL192(desCipher)

	key := make([]byte, 24)
	block := make([]byte, 16)
	rand.Read(key)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	if len(encrypted) != 16 {
		t.Errorf("Expected encrypted block size 16, got %d", len(encrypted))
	}

	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Error("Decrypted block does not match original")
		t.Errorf("Original: %x", block)
		t.Errorf("Decrypted: %x", decrypted)
	}
}

func TestDEAL256(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL256(desCipher)

	key := make([]byte, 32)
	block := make([]byte, 16)
	rand.Read(key)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	if len(encrypted) != 16 {
		t.Errorf("Expected encrypted block size 16, got %d", len(encrypted))
	}

	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Error("Decrypted block does not match original")
		t.Errorf("Original: %x", block)
		t.Errorf("Decrypted: %x", decrypted)
	}
}

func TestDESAdapter(t *testing.T) {
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

func TestDEALKeyExpander(t *testing.T) {
	testCases := []struct {
		name       string
		keySize    int
		wantRounds int
		wantError  bool
	}{
		{"128-bit key", 16, 6, false},
		{"192-bit key", 24, 6, false},
		{"256-bit key", 32, 8, false},
		{"Invalid key size", 20, 0, true},
		{"Invalid key size", 8, 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expander := NewDEALKeyExpander(tc.keySize)

			key := make([]byte, tc.keySize)
			rand.Read(key)

			subkeys, err := expander.ExpandKey(key)

			if (err != nil) != tc.wantError {
				t.Errorf("ExpandKey() error = %v, wantError %v", err, tc.wantError)
				return
			}

			if !tc.wantError {
				if len(subkeys) != tc.wantRounds {
					t.Errorf("Expected %d subkeys, got %d", tc.wantRounds, len(subkeys))
				}

				for i, subkey := range subkeys {
					if len(subkey) != 8 {
						t.Errorf("Subkey %d has wrong size: expected 8, got %d", i, len(subkey))
					}

					allZero := true
					for _, b := range subkey {
						if b != 0 {
							allZero = false
							break
						}
					}
					if allZero {
						t.Errorf("Subkey %d is all zeros", i)
					}
				}

				decryptionKeys, err := expander.ExpandDecryptionKeys(key)
				if err != nil {
					t.Errorf("ExpandDecryptionKeys failed: %v", err)
				}

				if len(decryptionKeys) != len(subkeys) {
					t.Errorf("Decryption keys count %d doesn't match encryption keys count %d",
						len(decryptionKeys), len(subkeys))
				}

				for i := 0; i < len(subkeys); i++ {
					if !bytes.Equal(decryptionKeys[i], subkeys[len(subkeys)-1-i]) {
						t.Errorf("Decryption key %d doesn't match reverse encryption key", i)
					}
				}
			}
		})
	}
}

func TestDEALFactory(t *testing.T) {
	factory := NewDEALFactory()

	testCases := []struct {
		name      string
		keySize   int
		wantError bool
	}{
		{"DEAL-128", 16, false},
		{"DEAL-192", 24, false},
		{"DEAL-256", 32, false},
		{"Invalid key size", 20, true},
		{"Invalid key size", 8, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cipher, err := factory.CreateDEAL(tc.keySize)

			if (err != nil) != tc.wantError {
				t.Errorf("CreateDEAL() error = %v, wantError %v", err, tc.wantError)
				return
			}

			if !tc.wantError && cipher == nil {
				t.Error("Expected cipher instance but got nil")
			}

			if !tc.wantError {
				key := make([]byte, tc.keySize)
				block := make([]byte, 16)
				rand.Read(key)
				rand.Read(block)

				if err := cipher.SetEncryptionKey(key); err != nil {
					t.Errorf("SetEncryptionKey failed: %v", err)
					return
				}

				encrypted, err := cipher.EncryptBlock(block)
				if err != nil {
					t.Errorf("EncryptBlock failed: %v", err)
					return
				}

				decrypted, err := cipher.DecryptBlock(encrypted)
				if err != nil {
					t.Errorf("DecryptBlock failed: %v", err)
					return
				}

				if !bytes.Equal(decrypted, block) {
					t.Error("Decrypted block does not match original")
				}
			}
		})
	}
}

func TestDEALRoundCounts(t *testing.T) {
	testCases := []struct {
		keySize    int
		wantRounds int
	}{
		{16, 6}, // DEAL-128
		{24, 6}, // DEAL-192
		{32, 8}, // DEAL-256
	}

	for _, tc := range testCases {
		t.Run(string(rune(tc.keySize)), func(t *testing.T) {
			expander := NewDEALKeyExpander(tc.keySize)
			if expander.rounds != tc.wantRounds {
				t.Errorf("For key size %d, expected %d rounds, got %d",
					tc.keySize, tc.wantRounds, expander.rounds)
			}

			key := make([]byte, tc.keySize)
			rand.Read(key)

			subkeys, err := expander.ExpandKey(key)
			if err != nil {
				t.Fatalf("ExpandKey failed: %v", err)
			}

			if len(subkeys) != tc.wantRounds {
				t.Errorf("Expected %d subkeys, got %d", tc.wantRounds, len(subkeys))
			}
		})
	}
}
