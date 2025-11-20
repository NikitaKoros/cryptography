package deal

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des/feistel"
)

// TestDEALBasicEncryptionDecryption проверяет базовое шифрование/дешифрование
func TestDEALBasicEncryptionDecryption(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	key := []byte("0123456789ABCDEF")       // 128-bit key
	plaintext := []byte("Hello, DEAL!1234") // 128-bit block

	// Устанавливаем ключ шифрования
	if err := deal.SetEncryptionKey(key); err != nil {
		t.Fatalf("Failed to set encryption key: %v", err)
	}

	// Шифруем
	ciphertext, err := deal.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Проверяем, что шифртекст отличается от открытого текста
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	// Устанавливаем ключ дешифрования
	if err := deal.SetDecryptionKey(key); err != nil {
		t.Fatalf("Failed to set decryption key: %v", err)
	}

	// Дешифруем
	decrypted, err := deal.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Проверяем, что расшифрованный текст совпадает с исходным
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match plaintext\nExpected: %x\nGot: %x",
			plaintext, decrypted)
	}
}

// TestDEALDifferentKeySizes проверяет работу с ключами разной длины
func TestDEALDifferentKeySizes(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	keySizes := []int{16, 24, 32}           // 128, 192, 256 bits
	plaintext := []byte("TestData12345678") // 128-bit block

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize*8), func(t *testing.T) {
			key := make([]byte, keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Шифрование
			if err := deal.SetEncryptionKey(key); err != nil {
				t.Fatalf("Failed to set encryption key: %v", err)
			}

			ciphertext, err := deal.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Дешифрование
			if err := deal.SetDecryptionKey(key); err != nil {
				t.Fatalf("Failed to set decryption key: %v", err)
			}

			decrypted, err := deal.DecryptBlock(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Decryption failed for key size %d bits", keySize*8)
			}
		})
	}
}

// TestDEALInvalidKeySize проверяет обработку некорректных размеров ключа
func TestDEALInvalidKeySize(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	invalidKeys := [][]byte{
		make([]byte, 8),  // 64 bits - too short
		make([]byte, 12), // 96 bits - invalid
		make([]byte, 20), // 160 bits - invalid
		make([]byte, 64), // 512 bits - too long
	}

	for _, key := range invalidKeys {
		if err := deal.SetEncryptionKey(key); err == nil {
			t.Errorf("Expected error for key size %d bytes, but got none", len(key))
		}
	}
}

// TestDEALInvalidBlockSize проверяет обработку блоков некорректного размера
func TestDEALInvalidBlockSize(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	key := make([]byte, 16)
	if err := deal.SetEncryptionKey(key); err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	invalidBlocks := [][]byte{
		make([]byte, 8),  // 64 bits - too short
		make([]byte, 12), // 96 bits - invalid
		make([]byte, 24), // 192 bits - too long
		make([]byte, 32), // 256 bits - too long
	}

	for _, block := range invalidBlocks {
		if _, err := deal.EncryptBlock(block); err == nil {
			t.Errorf("Expected error for block size %d bytes, but got none", len(block))
		}
	}
}

// TestDEALRandomData проверяет шифрование случайных данных
func TestDEALRandomData(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Тестируем 100 случайных блоков
	for i := 0; i < 100; i++ {
		plaintext := make([]byte, 16)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("Failed to generate plaintext: %v", err)
		}

		// Шифрование
		if err := deal.SetEncryptionKey(key); err != nil {
			t.Fatalf("Failed to set encryption key: %v", err)
		}

		ciphertext, err := deal.EncryptBlock(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Дешифрование
		if err := deal.SetDecryptionKey(key); err != nil {
			t.Fatalf("Failed to set decryption key: %v", err)
		}

		decrypted, err := deal.DecryptBlock(ciphertext)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Iteration %d: Decryption failed", i)
		}
	}
}

// TestDEALDeterminism проверяет детерминированность алгоритма
func TestDEALDeterminism(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	key := []byte("DeterministicKey")
	plaintext := []byte("DeterministicTxt")

	if err := deal.SetEncryptionKey(key); err != nil {
		t.Fatalf("Failed to set encryption key: %v", err)
	}

	// Шифруем один и тот же блок несколько раз
	var ciphertexts [][]byte
	for i := 0; i < 5; i++ {
		ciphertext, err := deal.EncryptBlock(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		ciphertexts = append(ciphertexts, ciphertext)
	}

	// Проверяем, что все шифртексты идентичны
	for i := 1; i < len(ciphertexts); i++ {
		if !bytes.Equal(ciphertexts[0], ciphertexts[i]) {
			t.Errorf("Encryption is not deterministic: iteration 0 vs %d", i)
		}
	}
}

// TestDEALAdapter проверяет работу адаптера DES
func TestDEALAdapter(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	adapter := NewDESAdapter(desImpl)

	block := make([]byte, 16)   // 128-bit block
	roundKey := make([]byte, 8) // 64-bit key

	if _, err := rand.Read(block); err != nil {
		t.Fatalf("Failed to generate block: %v", err)
	}
	if _, err := rand.Read(roundKey); err != nil {
		t.Fatalf("Failed to generate round key: %v", err)
	}

	// Выполняем раундовое преобразование
	result, err := adapter.EncryptRound(block, roundKey)
	if err != nil {
		t.Fatalf("Round encryption failed: %v", err)
	}

	// Проверяем, что результат имеет правильный размер
	if len(result) != 16 {
		t.Errorf("Expected result size 16, got %d", len(result))
	}

	// Проверяем, что результат отличается от входа
	if bytes.Equal(block, result) {
		t.Error("Round transformation should change the block")
	}
}

// TestDEALKeySchedule проверяет генерацию раундовых ключей
func TestDEALKeySchedule(t *testing.T) {
	desImpl := feistel.NewDESFeistel()
	keySchedule := NewDEALKeySchedule(desImpl)

	testCases := []struct {
		keySize        int
		expectedRounds int
	}{
		{16, 6}, // 128-bit key -> 6 rounds
		{24, 8}, // 192-bit key -> 8 rounds
		{32, 8}, // 256-bit key -> 8 rounds
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("KeySize_%d", tc.keySize*8), func(t *testing.T) {
			key := make([]byte, tc.keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			roundKeys, err := keySchedule.ExpandKey(key)
			if err != nil {
				t.Fatalf("Key expansion failed: %v", err)
			}

			// Проверяем количество раундовых ключей
			if len(roundKeys) != tc.expectedRounds {
				t.Errorf("Expected %d round keys, got %d",
					tc.expectedRounds, len(roundKeys))
			}

			// Проверяем размер каждого раундового ключа
			for i, rk := range roundKeys {
				if len(rk) != 8 {
					t.Errorf("Round key %d has size %d, expected 8", i, len(rk))
				}
			}
		})
	}
}

// BenchmarkDEALEncryption бенчмарк для шифрования
func BenchmarkDEALEncryption(b *testing.B) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	key := make([]byte, 16)
	plaintext := make([]byte, 16)
	rand.Read(key)
	rand.Read(plaintext)

	deal.SetEncryptionKey(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = deal.EncryptBlock(plaintext)
	}
}

// BenchmarkDEALDecryption бенчмарк для дешифрования
func BenchmarkDEALDecryption(b *testing.B) {
	desImpl := feistel.NewDESFeistel()
	deal := NewDEAL(desImpl)

	key := make([]byte, 16)
	plaintext := make([]byte, 16)
	rand.Read(key)
	rand.Read(plaintext)

	deal.SetEncryptionKey(key)
	ciphertext, _ := deal.EncryptBlock(plaintext)
	deal.SetDecryptionKey(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = deal.DecryptBlock(ciphertext)
	}
}
