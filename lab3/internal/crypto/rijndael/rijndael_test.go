package rijndael

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Тест создания Rijndael с корректными параметрами
func TestNewRijndael_ValidParameters(t *testing.T) {
	blockSizes := []int{16, 24, 32}
	keySizes := []int{16, 24, 32}
	modulus := byte(0x1B)

	for _, blockSize := range blockSizes {
		for _, keySize := range keySizes {
			cipher, err := NewRijndael(blockSize, keySize, modulus)
			if err != nil {
				t.Errorf("NewRijndael(%d, %d, 0x%02X) вернул ошибку: %v",
					blockSize, keySize, modulus, err)
			}
			if cipher == nil {
				t.Errorf("NewRijndael(%d, %d, 0x%02X) вернул nil",
					blockSize, keySize, modulus)
			}
			if cipher.BlockSize() != blockSize {
				t.Errorf("BlockSize() = %d; ожидалось %d", cipher.BlockSize(), blockSize)
			}
		}
	}
}

// Тест создания Rijndael с некорректными размерами блока
func TestNewRijndael_InvalidBlockSize(t *testing.T) {
	invalidBlockSizes := []int{8, 15, 17, 20, 33, 64}

	for _, blockSize := range invalidBlockSizes {
		cipher, err := NewRijndael(blockSize, 16, 0x1B)
		if err == nil {
			t.Errorf("NewRijndael(%d, 16, 0x1B) должен был вернуть ошибку", blockSize)
		}
		if cipher != nil {
			t.Errorf("NewRijndael(%d, 16, 0x1B) должен был вернуть nil", blockSize)
		}
	}
}

// Тест создания Rijndael с некорректными размерами ключа
func TestNewRijndael_InvalidKeySize(t *testing.T) {
	invalidKeySizes := []int{8, 15, 17, 20, 33, 64}

	for _, keySize := range invalidKeySizes {
		cipher, err := NewRijndael(16, keySize, 0x1B)
		if err == nil {
			t.Errorf("NewRijndael(16, %d, 0x1B) должен был вернуть ошибку", keySize)
		}
		if cipher != nil {
			t.Errorf("NewRijndael(16, %d, 0x1B) должен был вернуть nil", keySize)
		}
	}
}

// Тест создания Rijndael с некорректным модулем
func TestNewRijndael_InvalidModulus(t *testing.T) {
	cipher, err := NewRijndael(16, 16, 0x00)
	if err == nil {
		t.Error("NewRijndael с приводимым модулем должен был вернуть ошибку")
	}
	if cipher != nil {
		t.Error("NewRijndael с приводимым модулем должен был вернуть nil")
	}
}

// Тест установки ключа шифрования
func TestSetEncryptionKey_ValidKey(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)
	rand.Read(key)

	err := cipher.SetEncryptionKey(key)
	if err != nil {
		t.Errorf("SetEncryptionKey вернул ошибку: %v", err)
	}

	if cipher.roundKeys == nil {
		t.Error("roundKeys не был установлен после SetEncryptionKey")
	}
}

// Тест установки ключа шифрования с неверным размером
func TestSetEncryptionKey_InvalidSize(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	invalidKeys := [][]byte{
		make([]byte, 8),
		make([]byte, 15),
		make([]byte, 17),
		make([]byte, 32),
	}

	for _, key := range invalidKeys {
		err := cipher.SetEncryptionKey(key)
		if err == nil {
			t.Errorf("SetEncryptionKey должен был вернуть ошибку для ключа размером %d", len(key))
		}
	}
}

// Тест шифрования и дешифрования блока
func TestEncryptDecryptBlock(t *testing.T) {
	blockSizes := []int{16, 24, 32}
	keySizes := []int{16, 24, 32}
	modulus := byte(0x1B)

	for _, blockSize := range blockSizes {
		for _, keySize := range keySizes {
			cipher, _ := NewRijndael(blockSize, keySize, modulus)

			key := make([]byte, keySize)
			rand.Read(key)

			cipher.SetEncryptionKey(key)
			cipher.SetDecryptionKey(key)

			plaintext := make([]byte, blockSize)
			rand.Read(plaintext)

			ciphertext, err := cipher.EncryptBlock(plaintext)
			if err != nil {
				t.Errorf("EncryptBlock вернул ошибку: %v", err)
				continue
			}

			decrypted, err := cipher.DecryptBlock(ciphertext)
			if err != nil {
				t.Errorf("DecryptBlock вернул ошибку: %v", err)
				continue
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Дешифрование не восстановило исходный текст для блока %d бит, ключа %d бит",
					blockSize*8, keySize*8)
			}
		}
	}
}

// Тест шифрования без установленного ключа
func TestEncryptBlock_NoKey(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	plaintext := make([]byte, 16)

	_, err := cipher.EncryptBlock(plaintext)
	if err == nil {
		t.Error("EncryptBlock должен был вернуть ошибку без установленного ключа")
	}
}

// Тест дешифрования без установленного ключа
func TestDecryptBlock_NoKey(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	ciphertext := make([]byte, 16)

	_, err := cipher.DecryptBlock(ciphertext)
	if err == nil {
		t.Error("DecryptBlock должен был вернуть ошибку без установленного ключа")
	}
}

// Тест шифрования блока неверного размера
func TestEncryptBlock_InvalidSize(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)
	cipher.SetEncryptionKey(key)

	invalidBlocks := [][]byte{
		make([]byte, 8),
		make([]byte, 15),
		make([]byte, 17),
		make([]byte, 32),
	}

	for _, block := range invalidBlocks {
		_, err := cipher.EncryptBlock(block)
		if err == nil {
			t.Errorf("EncryptBlock должен был вернуть ошибку для блока размером %d", len(block))
		}
	}
}

// Тест что шифрование изменяет данные
func TestEncryptBlock_ChangesData(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)
	rand.Read(key)
	cipher.SetEncryptionKey(key)

	plaintext := make([]byte, 16)
	rand.Read(plaintext)

	ciphertext, _ := cipher.EncryptBlock(plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Шифрование не изменило данные (plaintext == ciphertext)")
	}
}

// Тест что разные ключи дают разные результаты
func TestEncryptBlock_DifferentKeys(t *testing.T) {
	cipher1, _ := NewRijndael(16, 16, 0x1B)
	cipher2, _ := NewRijndael(16, 16, 0x1B)

	key1 := make([]byte, 16)
	key2 := make([]byte, 16)
	rand.Read(key1)
	rand.Read(key2)

	cipher1.SetEncryptionKey(key1)
	cipher2.SetEncryptionKey(key2)

	plaintext := make([]byte, 16)
	rand.Read(plaintext)

	ciphertext1, _ := cipher1.EncryptBlock(plaintext)
	ciphertext2, _ := cipher2.EncryptBlock(plaintext)

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Разные ключи дали одинаковый результат шифрования")
	}
}

// Тест что разные модули дают разные результаты
func TestEncryptBlock_DifferentModuli(t *testing.T) {
	cipher1, _ := NewRijndael(16, 16, 0x1B)
	cipher2, _ := NewRijndael(16, 16, 0x1D)

	key := make([]byte, 16)
	rand.Read(key)

	cipher1.SetEncryptionKey(key)
	cipher2.SetEncryptionKey(key)

	plaintext := make([]byte, 16)
	rand.Read(plaintext)

	ciphertext1, _ := cipher1.EncryptBlock(plaintext)
	ciphertext2, _ := cipher2.EncryptBlock(plaintext)

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Разные модули дали одинаковый результат шифрования")
	}
}

// Тест addRoundKey
func TestAddRoundKey(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)

	state := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	roundKey := []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}

	expected := make([]byte, 16)
	for i := range state {
		expected[i] = state[i] ^ roundKey[i]
	}

	cipher.addRoundKey(state, roundKey)

	if !bytes.Equal(state, expected) {
		t.Errorf("addRoundKey дал неожиданный результат")
	}
}

// Тест что addRoundKey обратима
func TestAddRoundKey_Reversible(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)

	original := make([]byte, 16)
	rand.Read(original)
	state := make([]byte, 16)
	copy(state, original)

	roundKey := make([]byte, 16)
	rand.Read(roundKey)

	cipher.addRoundKey(state, roundKey)
	cipher.addRoundKey(state, roundKey)

	if !bytes.Equal(state, original) {
		t.Error("Двойное применение addRoundKey не восстановило исходное состояние")
	}
}

// Тест shiftRows и invShiftRows
func TestShiftRows_InvShiftRows(t *testing.T) {
	blockSizes := []int{16, 24, 32}

	for _, blockSize := range blockSizes {
		cipher, _ := NewRijndael(blockSize, blockSize, 0x1B)

		original := make([]byte, blockSize)
		rand.Read(original)
		state := make([]byte, blockSize)
		copy(state, original)

		cipher.shiftRows(state)
		cipher.invShiftRows(state)

		if !bytes.Equal(state, original) {
			t.Errorf("shiftRows -> invShiftRows не восстановил исходное состояние для блока %d бит",
				blockSize*8)
		}
	}
}

// Тест mixColumns и invMixColumns
func TestMixColumns_InvMixColumns(t *testing.T) {
	blockSizes := []int{16, 24, 32}

	for _, blockSize := range blockSizes {
		cipher, _ := NewRijndael(blockSize, blockSize, 0x1B)

		original := make([]byte, blockSize)
		rand.Read(original)
		state := make([]byte, blockSize)
		copy(state, original)

		cipher.mixColumns(state)
		cipher.invMixColumns(state)

		if !bytes.Equal(state, original) {
			t.Errorf("mixColumns -> invMixColumns не восстановил исходное состояние для блока %d бит",
				blockSize*8)
		}
	}
}

// Тест calculateRounds
func TestCalculateRounds(t *testing.T) {
	tests := []struct {
		Nb, Nk, expected int
	}{
		{4, 4, 10},  // AES-128
		{4, 6, 12},  // AES-192
		{4, 8, 14},  // AES-256
		{6, 4, 12},  // Rijndael-192-128
		{6, 6, 12},  // Rijndael-192-192
		{8, 4, 14},  // Rijndael-256-128
		{8, 8, 14},  // Rijndael-256-256
	}

	for _, tt := range tests {
		result := calculateRounds(tt.Nb, tt.Nk)
		if result != tt.expected {
			t.Errorf("calculateRounds(%d, %d) = %d; ожидалось %d",
				tt.Nb, tt.Nk, result, tt.expected)
		}
	}
}

// Тест что ключи расширяются корректно
func TestExpandKey(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)
	rand.Read(key)

	roundKeys, err := cipher.expandKey(key)
	if err != nil {
		t.Fatalf("expandKey вернул ошибку: %v", err)
	}

	// Для AES-128 должно быть 11 раундовых ключей (Nr + 1 = 10 + 1)
	expectedCount := cipher.Nr + 1
	if len(roundKeys) != expectedCount {
		t.Errorf("expandKey вернул %d ключей; ожидалось %d", len(roundKeys), expectedCount)
	}

	// Каждый раундовый ключ должен иметь размер блока
	for i, roundKey := range roundKeys {
		if len(roundKey) != cipher.blockSize {
			t.Errorf("roundKey[%d] имеет размер %d; ожидалось %d",
				i, len(roundKey), cipher.blockSize)
		}
	}
}

// Тест что нулевой ключ дает корректные раундовые ключи
func TestExpandKey_ZeroKey(t *testing.T) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16) // Все нули

	roundKeys, err := cipher.expandKey(key)
	if err != nil {
		t.Fatalf("expandKey вернул ошибку: %v", err)
	}

	// Первый раундовый ключ должен быть равен исходному ключу
	if !bytes.Equal(roundKeys[0], key) {
		t.Error("Первый раундовый ключ не равен исходному ключу")
	}

	// Последующие раундовые ключи не должны быть нулевыми
	for i := 1; i < len(roundKeys); i++ {
		allZero := true
		for _, b := range roundKeys[i] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Errorf("roundKey[%d] полностью нулевой", i)
		}
	}
}

// Бенчмарк для создания Rijndael
func BenchmarkNewRijndael(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewRijndael(16, 16, 0x1B)
	}
}

// Бенчмарк для шифрования блока
func BenchmarkEncryptBlock(b *testing.B) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)
	plaintext := make([]byte, 16)
	cipher.SetEncryptionKey(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.EncryptBlock(plaintext)
	}
}

// Бенчмарк для дешифрования блока
func BenchmarkDecryptBlock(b *testing.B) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)
	ciphertext := make([]byte, 16)
	cipher.SetDecryptionKey(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.DecryptBlock(ciphertext)
	}
}

// Бенчмарк для расширения ключа
func BenchmarkExpandKey(b *testing.B) {
	cipher, _ := NewRijndael(16, 16, 0x1B)
	key := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.expandKey(key)
	}
}
