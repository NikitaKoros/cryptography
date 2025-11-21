package feistel

import (
	"bytes"
	"testing"
)

type MockKeyExpander struct {
	rounds int
}

func (m *MockKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	subkeys := make([][]byte, m.rounds)
	for i := 0; i < m.rounds; i++ {
		subkeys[i] = append([]byte{}, key...)
	}
	return subkeys, nil
}

type MockRoundEncrypter struct{}

func (m *MockRoundEncrypter) EncryptRound(block []byte, roundKey []byte) ([]byte, error) {
	result := make([]byte, len(block))
	for i := range block {
		result[i] = block[i] ^ roundKey[i%len(roundKey)]
	}
	return result, nil
}

func TestFeistelNetwork_SetEncryptionKey(t *testing.T) {
	keyExpander := &MockKeyExpander{rounds: 4}
	roundEncrypter := &MockRoundEncrypter{}
	fn := NewFeistelNetwork(keyExpander, roundEncrypter, 4)

	key := []byte{0x01, 0x02, 0x03, 0x04}
	err := fn.SetEncryptionKey(key)
	if err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	if len(fn.EncryptKeys) != 4 {
		t.Errorf("Expected 4 encrypt keys, got %d", len(fn.EncryptKeys))
	}

	if len(fn.DecryptKeys) != 4 {
		t.Errorf("Expected 4 decrypt keys, got %d", len(fn.DecryptKeys))
	}

	if !bytes.Equal(fn.EncryptKeys[0], fn.DecryptKeys[3]) {
		t.Error("Decrypt keys are not in reverse order")
	}
}

func TestFeistelNetwork_EncryptDecrypt(t *testing.T) {
	keyExpander := &MockKeyExpander{rounds: 4}
	roundEncrypter := &MockRoundEncrypter{}
	fn := NewFeistelNetwork(keyExpander, roundEncrypter, 4)

	key := []byte{0x01, 0x02, 0x03, 0x04}
	err := fn.SetEncryptionKey(key)
	if err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	plaintext := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	ciphertext, err := fn.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := fn.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption failed: got %x, want %x", decrypted, plaintext)
	}
}

func TestFeistelNetwork_NoKeySet(t *testing.T) {
	keyExpander := &MockKeyExpander{rounds: 4}
	roundEncrypter := &MockRoundEncrypter{}
	fn := NewFeistelNetwork(keyExpander, roundEncrypter, 4)

	plaintext := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	_, err := fn.EncryptBlock(plaintext)
	if err == nil {
		t.Error("Expected error when key not set, got none")
	}
}

func TestFeistelNetwork_NilKeyExpander(t *testing.T) {
	fn := NewFeistelNetwork(nil, &MockRoundEncrypter{}, 4)

	key := []byte{0x01, 0x02, 0x03, 0x04}
	err := fn.SetEncryptionKey(key)
	if err == nil {
		t.Error("Expected error with nil key expander, got none")
	}
}

func TestFeistelNetwork_NilRoundEncrypter(t *testing.T) {
	keyExpander := &MockKeyExpander{rounds: 4}
	fn := NewFeistelNetwork(keyExpander, nil, 4)

	key := []byte{0x01, 0x02, 0x03, 0x04}
	err := fn.SetEncryptionKey(key)
	if err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	plaintext := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	_, err = fn.EncryptBlock(plaintext)
	if err == nil {
		t.Error("Expected error with nil round encrypter, got none")
	}
}
