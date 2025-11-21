package deal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

// TestDESAdapter тестирует адаптер DES
func TestDESAdapter(t *testing.T) {
	desCipher := des.NewDES()
	adapter := NewDESAdapter(desCipher)

	// Тестовый ключ для DES
	desKey := make([]byte, 8)
	for i := range desKey {
		desKey[i] = byte(i)
	}

	// Тестовый блок для DEAL (16 байт)
	block := make([]byte, 16)
	for i := range block {
		block[i] = byte(i + 10)
	}

	// Тестируем раундовое шифрование
	result, err := adapter.EncryptRound(block, desKey)
	if err != nil {
		t.Fatalf("EncryptRound failed: %v", err)
	}

	if len(result) != 16 {
		t.Errorf("Expected result length 16, got %d", len(result))
	}

	// Проверяем, что результат отличается от исходного блока
	if bytes.Equal(result, block) {
		t.Error("Expected encrypted result to be different from original block")
	}
}

// TestDEALKeyExpander тестирует расширение ключа
func TestDEALKeyExpander(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		key     []byte
		wantErr bool
	}{
		{
			name:    "DEAL-128 valid key",
			keySize: 16,
			key:     make([]byte, 16),
		},
		{
			name:    "DEAL-192 valid key",
			keySize: 24,
			key:     make([]byte, 24),
		},
		{
			name:    "DEAL-256 valid key",
			keySize: 32,
			key:     make([]byte, 32),
		},
		{
			name:    "DEAL-128 invalid key size",
			keySize: 16,
			key:     make([]byte, 8), // Неправильный размер
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expander := NewDEALKeyExpander(tt.keySize, 16)

			subkeys, err := expander.ExpandKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(subkeys) != expander.rounds {
					t.Errorf("Expected %d subkeys, got %d", expander.rounds, len(subkeys))
				}

				// Проверяем, что все подключа имеют правильный размер
				for i, subkey := range subkeys {
					if len(subkey) != 8 {
						t.Errorf("Subkey %d has wrong size: expected 8, got %d", i, len(subkey))
					}
				}
			}
		})
	}
}

// TestDEAL128 тестирует DEAL-128
func TestDEAL128(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	// Тестовый ключ (128 бит)
	key := make([]byte, 16)
	rand.Read(key)

	// Тестовый блок (128 бит)
	block := make([]byte, 16)
	rand.Read(block)

	// Устанавливаем ключ
	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Тестируем шифрование
	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	if len(encrypted) != 16 {
		t.Errorf("Expected encrypted block length 16, got %d", len(encrypted))
	}

	// Проверяем, что зашифрованный блок отличается от исходного
	if bytes.Equal(encrypted, block) {
		t.Error("Encrypted block should be different from original")
	}

	// Тестируем дешифрование
	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if len(decrypted) != 16 {
		t.Errorf("Expected decrypted block length 16, got %d", len(decrypted))
	}

	// Проверяем, что дешифрованный блок совпадает с исходным
	if !bytes.Equal(decrypted, block) {
		t.Error("Decrypted block does not match original")
		t.Errorf("Original: %x", block)
		t.Errorf("Decrypted: %x", decrypted)
	}
}

// TestDEAL192 тестирует DEAL-192
func TestDEAL192(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL192(desCipher)

	// Тестовый ключ (192 бита)
	key := make([]byte, 24)
	rand.Read(key)

	// Тестовый блок (128 бит)
	block := make([]byte, 16)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Error("Decrypted block does not match original for DEAL-192")
	}
}

// TestDEAL256 тестирует DEAL-256
func TestDEAL256(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL256(desCipher)

	// Тестовый ключ (256 бит)
	key := make([]byte, 32)
	rand.Read(key)

	// Тестовый блок (128 бит)
	block := make([]byte, 16)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Error("Decrypted block does not match original for DEAL-256")
	}
}

// TestDEALInvalidBlockSize тестирует обработку неверных размеров блоков
func TestDEALInvalidBlockSize(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	key := make([]byte, 16)
	rand.Read(key)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Тестируем слишком маленький блок
	smallBlock := make([]byte, 8)
	_, err := dealCipher.EncryptBlock(smallBlock)
	if err == nil {
		t.Error("Expected error for small block size")
	}

	// Тестируем слишком большой блок
	largeBlock := make([]byte, 24)
	_, err = dealCipher.EncryptBlock(largeBlock)
	if err == nil {
		t.Error("Expected error for large block size")
	}
}

// TestDEALInvalidKeySize тестирует обработку неверных размеров ключей
func TestDEALInvalidKeySize(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	// Слишком маленький ключ
	smallKey := make([]byte, 8)
	err := dealCipher.SetEncryptionKey(smallKey)
	if err == nil {
		t.Error("Expected error for small key size")
	}

	// Слишком большой ключ
	largeKey := make([]byte, 24)
	err = dealCipher.SetEncryptionKey(largeKey)
	if err == nil {
		t.Error("Expected error for large key size")
	}
}

// TestDEALMultipleBlocks тестирует шифрование нескольких блоков
func TestDEALMultipleBlocks(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	key := make([]byte, 16)
	rand.Read(key)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Тестируем несколько различных блоков
	blocks := [][]byte{
		make([]byte, 16),
		make([]byte, 16),
		make([]byte, 16),
	}

	for i := range blocks {
		rand.Read(blocks[i])
	}

	for i, block := range blocks {
		encrypted, err := dealCipher.EncryptBlock(block)
		if err != nil {
			t.Fatalf("EncryptBlock failed for block %d: %v", i, err)
		}

		decrypted, err := dealCipher.DecryptBlock(encrypted)
		if err != nil {
			t.Fatalf("DecryptBlock failed for block %d: %v", i, err)
		}

		if !bytes.Equal(decrypted, block) {
			t.Errorf("Block %d: decrypted does not match original", i)
		}
	}
}

// TestDEALConsistency тестирует консистентность шифрования
func TestDEALConsistency(t *testing.T) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	key := make([]byte, 16)
	block := make([]byte, 16)
	rand.Read(key)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Шифруем один и тот же блок несколько раз
	var firstEncryption []byte
	for i := 0; i < 5; i++ {
		encrypted, err := dealCipher.EncryptBlock(block)
		if err != nil {
			t.Fatalf("EncryptBlock failed on iteration %d: %v", i, err)
		}

		if i == 0 {
			firstEncryption = encrypted
		} else {
			// DEAL должен быть детерминированным - одинаковый вывод для одинакового ввода
			if !bytes.Equal(encrypted, firstEncryption) {
				t.Error("DEAL encryption is not consistent")
			}
		}

		// Всегда должен правильно дешифроваться
		decrypted, err := dealCipher.DecryptBlock(encrypted)
		if err != nil {
			t.Fatalf("DecryptBlock failed on iteration %d: %v", i, err)
		}

		if !bytes.Equal(decrypted, block) {
			t.Error("Decryption failed to recover original block")
		}
	}
}

// TestDEALWithCustomBlockSize тестирует DEAL с пользовательским размером блока
func TestDEALWithCustomBlockSize(t *testing.T) {
	desCipher := des.NewDES()

	// Тестируем различные пользовательские размеры
	testCases := []struct {
		name      string
		keySize   int
		blockSize int
	}{
		{"Custom 192-bit block", 16, 24},
		{"Custom 256-bit block", 24, 32},
		{"Custom 128-bit block with 256-bit key", 32, 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dealCipher := NewDEALWithCustomBlockSize(desCipher, tc.keySize, tc.blockSize)

			key := make([]byte, tc.keySize)
			block := make([]byte, tc.blockSize)
			rand.Read(key)
			rand.Read(block)

			if err := dealCipher.SetEncryptionKey(key); err != nil {
				t.Fatalf("SetEncryptionKey failed: %v", err)
			}

			encrypted, err := dealCipher.EncryptBlock(block)
			if err != nil {
				t.Fatalf("EncryptBlock failed: %v", err)
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
			}
		})
	}
}

// TestDEALFactory тестирует фабрику DEAL
func TestDEALFactory(t *testing.T) {
	factory := NewDEALFactory()

	tests := []struct {
		name      string
		keySize   int
		blockSize int
		wantErr   bool
	}{
		{"DEAL-128", 16, 16, false},
		{"DEAL-192", 24, 16, false},
		{"DEAL-256", 32, 16, false},
		{"Invalid key size", 20, 16, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := factory.CreateDEAL(tt.keySize, tt.blockSize)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateDEAL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cipher == nil {
				t.Error("Expected cipher to be non-nil")
			}

			if !tt.wantErr {
				// Проверяем базовую функциональность
				key := make([]byte, tt.keySize)
				block := make([]byte, tt.blockSize)
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
					t.Error("Factory-created cipher failed basic encryption/decryption test")
				}
			}
		})
	}
}

// BenchmarkDEALEncrypt бенчмарк для шифрования DEAL
func BenchmarkDEALEncrypt(b *testing.B) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	key := make([]byte, 16)
	block := make([]byte, 16)
	rand.Read(key)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		b.Fatalf("SetEncryptionKey failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dealCipher.EncryptBlock(block)
		if err != nil {
			b.Fatalf("EncryptBlock failed: %v", err)
		}
	}
}

// BenchmarkDEALDecrypt бенчмарк для дешифрования DEAL
func BenchmarkDEALDecrypt(b *testing.B) {
	desCipher := des.NewDES()
	dealCipher := NewDEAL128(desCipher)

	key := make([]byte, 16)
	block := make([]byte, 16)
	rand.Read(key)
	rand.Read(block)

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		b.Fatalf("SetEncryptionKey failed: %v", err)
	}

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		b.Fatalf("EncryptBlock failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dealCipher.DecryptBlock(encrypted)
		if err != nil {
			b.Fatalf("DecryptBlock failed: %v", err)
		}
	}
}
