package rsa

import (
	"math/big"
	"testing"
)

func TestRSAEncryptDecrypt(t *testing.T) {
	service := NewService(TestTypeMillerRabin, 0.99, 256)

	err := service.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	publicKey, _ := service.GetPublicKey()
	privateKey, _ := service.GetPrivateKey()

	message := big.NewInt(42)

	ciphertext, err := service.Encrypt(message, publicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := service.Decrypt(ciphertext, privateKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted.Cmp(message) != 0 {
		t.Errorf("Decrypted message doesn't match original: got %d, want %d", decrypted, message)
	}
}

func TestRSAEncryptDecryptBytes(t *testing.T) {
	service := NewService(TestTypeMillerRabin, 0.99, 256)

	err := service.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	publicKey, _ := service.GetPublicKey()
	privateKey, _ := service.GetPrivateKey()

	message := []byte("Hello, RSA!")

	ciphertext, err := service.EncryptBytes(message, publicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := service.DecryptBytes(ciphertext, privateKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(message) {
		t.Errorf("Decrypted message doesn't match original: got %s, want %s", decrypted, message)
	}
}

func TestKeyGeneration(t *testing.T) {
	service := NewService(TestTypeMillerRabin, 0.99, 256)

	err := service.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	privateKey, _ := service.GetPrivateKey()

	// Проверка защиты от атаки Ферма
	diff := new(big.Int).Sub(privateKey.P, privateKey.Q)
	diff.Abs(diff)
	minDiff := new(big.Int).Lsh(big.NewInt(1), uint(512/4))

	if diff.Cmp(minDiff) <= 0 {
		t.Error("Key generation failed Fermat protection check")
	}

	// Проверка, что p*q = n
	n := new(big.Int).Mul(privateKey.P, privateKey.Q)
	if n.Cmp(privateKey.N) != 0 {
		t.Error("P * Q != N")
	}
}
