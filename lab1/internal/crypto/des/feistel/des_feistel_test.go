package feistel

import (
	"bytes"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func TestDESFeistel_EncryptDecrypt(t *testing.T) {
	des := NewDESFeistel()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	err := des.SetEncryptionKey(key)
	if err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	ciphertext, err := des.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := des.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption failed: got %x, want %x", decrypted, plaintext)
	}
}

func TestDESFeistel_CompareWithOriginal(t *testing.T) {
	desOriginal := des.NewDES()
	desFeistel := NewDESFeistel()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	if err := desOriginal.SetEncryptionKey(key); err != nil {
		t.Fatalf("Original SetEncryptionKey failed: %v", err)
	}
	if err := desFeistel.SetEncryptionKey(key); err != nil {
		t.Fatalf("Feistel SetEncryptionKey failed: %v", err)
	}

	ciphertextOriginal, err := desOriginal.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("Original EncryptBlock failed: %v", err)
	}

	ciphertextFeistel, err := desFeistel.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("Feistel EncryptBlock failed: %v", err)
	}

	if !bytes.Equal(ciphertextOriginal, ciphertextFeistel) {
		t.Errorf("Ciphertexts don't match:\nOriginal: %x\nFeistel:  %x", ciphertextOriginal, ciphertextFeistel)
	}

	decryptedOriginal, err := desOriginal.DecryptBlock(ciphertextOriginal)
	if err != nil {
		t.Fatalf("Original DecryptBlock failed: %v", err)
	}

	decryptedFeistel, err := desFeistel.DecryptBlock(ciphertextFeistel)
	if err != nil {
		t.Fatalf("Feistel DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedOriginal) {
		t.Errorf("Original decryption failed: got %x, want %x", decryptedOriginal, plaintext)
	}

	if !bytes.Equal(plaintext, decryptedFeistel) {
		t.Errorf("Feistel decryption failed: got %x, want %x", decryptedFeistel, plaintext)
	}
}

func TestDESFeistel_InvalidKeySize(t *testing.T) {
	des := NewDESFeistel()

	invalidKey := []byte{0x01, 0x02, 0x03}
	err := des.SetEncryptionKey(invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size, got none")
	}
}

func TestDESFeistel_InvalidBlockSize(t *testing.T) {
	des := NewDESFeistel()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	err := des.SetEncryptionKey(key)
	if err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	invalidBlock := []byte{0x01, 0x02, 0x03}
	_, err = des.EncryptBlock(invalidBlock)
	if err == nil {
		t.Error("Expected error for invalid block size, got none")
	}
}

func TestDESFeistel_MultipleBlocks(t *testing.T) {
	des := NewDESFeistel()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	err := des.SetEncryptionKey(key)
	if err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	testBlocks := [][]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
	}

	for i, plaintext := range testBlocks {
		ciphertext, err := des.EncryptBlock(plaintext)
		if err != nil {
			t.Fatalf("Block %d: EncryptBlock failed: %v", i, err)
		}

		decrypted, err := des.DecryptBlock(ciphertext)
		if err != nil {
			t.Fatalf("Block %d: DecryptBlock failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Block %d: Decryption failed: got %x, want %x", i, decrypted, plaintext)
		}
	}
}

func BenchmarkDESFeistel_Encrypt(b *testing.B) {
	des := NewDESFeistel()
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	des.SetEncryptionKey(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = des.EncryptBlock(plaintext)
	}
}

func BenchmarkDESFeistel_Decrypt(b *testing.B) {
	des := NewDESFeistel()
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	des.SetEncryptionKey(key)
	ciphertext, _ := des.EncryptBlock(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = des.DecryptBlock(ciphertext)
	}
}
