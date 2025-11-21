package deal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

// TestDESAdapterEdgeCases тестирует граничные случаи адаптера DES
func TestDESAdapterEdgeCases(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	tests := []struct {
		name      string
		block     []byte
		roundKey  []byte
		wantError bool
	}{
		{
			name:      "Valid 16-byte input",
			block:     make([]byte, 16),
			roundKey:  make([]byte, 8),
			wantError: false,
		},
		{
			name:      "Valid 24-byte input",
			block:     make([]byte, 24),
			roundKey:  make([]byte, 8),
			wantError: false,
		},
		{
			name:      "Valid 32-byte input",
			block:     make([]byte, 32),
			roundKey:  make([]byte, 8),
			wantError: false,
		},
		{
			name:      "Block too small",
			block:     make([]byte, 8),
			roundKey:  make([]byte, 8),
			wantError: true,
		},
		{
			name:      "Block too large",
			block:     make([]byte, 64),
			roundKey:  make([]byte, 8),
			wantError: true,
		},
		{
			name:      "Invalid block size (not multiple of 8)",
			block:     make([]byte, 18),
			roundKey:  make([]byte, 8),
			wantError: true,
		},
		{
			name:      "Invalid round key size",
			block:     make([]byte, 16),
			roundKey:  make([]byte, 16),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Заполняем случайными данными
			rand.Read(tt.block)
			rand.Read(tt.roundKey)

			_, err := adapter.EncryptRound(tt.block, tt.roundKey)

			if (err != nil) != tt.wantError {
				t.Errorf("EncryptRound() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestDESAdapterDeterministic тестирует детерминированность адаптера
func TestDESAdapterDeterministic(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	block := make([]byte, 16)
	roundKey := make([]byte, 8)
	rand.Read(block)
	rand.Read(roundKey)

	// Многократное выполнение с одинаковыми входными данными должно давать одинаковый результат
	firstResult, err := adapter.EncryptRound(block, roundKey)
	if err != nil {
		t.Fatalf("First EncryptRound failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		result, err := adapter.EncryptRound(block, roundKey)
		if err != nil {
			t.Fatalf("EncryptRound iteration %d failed: %v", i, err)
		}

		if !bytes.Equal(result, firstResult) {
			t.Errorf("EncryptRound is not deterministic at iteration %d", i)
		}
	}
}
