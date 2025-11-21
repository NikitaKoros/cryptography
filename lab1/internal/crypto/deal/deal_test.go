package deal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

// TestDEALWithCustomBlockSize тестирует DEAL с пользовательским размером блока
func TestDEALWithCustomBlockSize(t *testing.T) {
	desCipher := des.NewDES()

	// Тестируем различные пользовательские размеры (только поддерживаемые)
	testCases := []struct {
		name      string
		keySize   int
		blockSize int
		wantError bool
	}{
		{"Standard 128-bit block", 16, 16, false},
		{"192-bit block", 16, 24, false},
		{"256-bit block", 24, 32, false},
		{"Odd block size should fail", 16, 17, true},
		{"Small block size should fail", 16, 8, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dealCipher := NewDEALWithCustomBlockSize(desCipher, tc.keySize, tc.blockSize)

			key := make([]byte, tc.keySize)
			block := make([]byte, tc.blockSize)
			rand.Read(key)
			rand.Read(block)

			if err := dealCipher.SetEncryptionKey(key); err != nil {
				if !tc.wantError {
					t.Fatalf("SetEncryptionKey failed: %v", err)
				}
				return
			}

			encrypted, err := dealCipher.EncryptBlock(block)
			if err != nil {
				if !tc.wantError {
					t.Fatalf("EncryptBlock failed: %v", err)
				}
				return
			}

			if tc.wantError {
				t.Error("Expected error but encryption succeeded")
				return
			}

			if len(encrypted) != tc.blockSize {
				t.Errorf("Expected encrypted block size %d, got %d", tc.blockSize, len(encrypted))
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
		})
	}
}

// TestDESAdapterDifferentBlockSizes тестирует адаптер с разными размерами блоков
func TestDESAdapterDifferentBlockSizes(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	testCases := []struct {
		name      string
		blockSize int
		wantError bool
	}{
		{"16-byte block", 16, false},
		{"24-byte block", 24, false},
		{"32-byte block", 32, false},
		{"48-byte block", 48, false},
		{"Odd block size", 15, true},
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

			if !tc.wantError {
				if len(result) != tc.blockSize {
					t.Errorf("Expected result length %d, got %d", tc.blockSize, len(result))
				}

				// Проверяем, что результат отличается от исходного блока
				if bytes.Equal(result, block) {
					t.Error("Expected encrypted result to be different from original block")
				}
			}
		})
	}
}

// TestDEALKeyExpanderDifferentSizes тестирует экспандер ключей с разными размерами
func TestDEALKeyExpanderDifferentSizes(t *testing.T) {
	testCases := []struct {
		name      string
		keySize   int
		blockSize int
		wantError bool
	}{
		{"128-bit key, 128-bit block", 16, 16, false},
		{"192-bit key, 128-bit block", 24, 16, false},
		{"256-bit key, 128-bit block", 32, 16, false},
		{"128-bit key, 192-bit block", 16, 24, false},
		{"128-bit key, 256-bit block", 16, 32, false},
		{"Invalid key size", 20, 16, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expander := NewDEALKeyExpander(tc.keySize, tc.blockSize)

			key := make([]byte, tc.keySize)
			rand.Read(key)

			subkeys, err := expander.ExpandKey(key)

			if (err != nil) != tc.wantError {
				t.Errorf("ExpandKey() error = %v, wantError %v", err, tc.wantError)
				return
			}

			if !tc.wantError {
				if len(subkeys) != expander.rounds {
					t.Errorf("Expected %d subkeys, got %d", expander.rounds, len(subkeys))
				}

				// Проверяем, что все подключа имеют правильный размер (8 байт для DES)
				for i, subkey := range subkeys {
					if len(subkey) != 8 {
						t.Errorf("Subkey %d has wrong size: expected 8, got %d", i, len(subkey))
					}

					// Проверяем, что подключи не нулевые
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
			}
		})
	}
}

// TestDESAdapterConsistency тестирует консистентность адаптера
func TestDESAdapterConsistency(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	block := make([]byte, 24) // 192-битный блок
	roundKey := make([]byte, 8)
	rand.Read(block)
	rand.Read(roundKey)

	// Многократное выполнение с одинаковыми входными данными должно давать одинаковый результат
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
