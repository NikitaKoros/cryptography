package frog

import (
	"bytes"
	"testing"
)

func TestFROGBasic(t *testing.T) {
	// Тест с нулевым ключом и нулевым блоком
	key := make([]byte, 16)
	plaintext := make([]byte, BlockSize)

	frog, err := New(key)
	if err != nil {
		t.Fatalf("Ошибка создания FROG: %v", err)
	}

	ciphertext, err := frog.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("Ошибка шифрования: %v", err)
	}

	decrypted, err := frog.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("Ошибка дешифрования: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Дешифрованный текст не совпадает с исходным")
		t.Errorf("Ожидалось: %v", plaintext)
		t.Errorf("Получено: %v", decrypted)
	}
}

func TestFROGDifferentKeySizes(t *testing.T) {
	keySizes := []int{16, 24, 32, 40}
	plaintext := []byte("Test message!!!!")

	for _, keySize := range keySizes {
		t.Run(string(rune(keySize)), func(t *testing.T) {
			key := make([]byte, keySize)
			for i := range key {
				key[i] = byte(i)
			}

			frog, err := New(key)
			if err != nil {
				t.Fatalf("Ошибка создания FROG с ключом %d байт: %v", keySize, err)
			}

			ciphertext, err := frog.EncryptBlock(plaintext)
			if err != nil {
				t.Fatalf("Ошибка шифрования: %v", err)
			}

			decrypted, err := frog.DecryptBlock(ciphertext)
			if err != nil {
				t.Fatalf("Ошибка дешифрования: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Дешифрованный текст не совпадает с исходным для ключа %d байт", keySize)
			}
		})
	}
}

func TestFROGKnownVector(t *testing.T) {
	// Тест с ключом размером 24 байта
	key := make([]byte, 24)
	plaintext := make([]byte, BlockSize)

	frog, err := New(key)
	if err != nil {
		t.Fatalf("Ошибка создания FROG: %v", err)
	}

	ciphertext, err := frog.EncryptBlock(plaintext)
	if err != nil {
		t.Fatalf("Ошибка шифрования: %v", err)
	}

	// Проверяем обратное преобразование
	decrypted, err := frog.DecryptBlock(ciphertext)
	if err != nil {
		t.Fatalf("Ошибка дешифрования: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Дешифрованный текст не совпадает с исходным")
		t.Errorf("Ожидалось: %v", plaintext)
		t.Errorf("Получено: %v", decrypted)
	}
}

func TestFROGInvalidBlockSize(t *testing.T) {
	key := make([]byte, 16)
	frog, err := New(key)
	if err != nil {
		t.Fatalf("Ошибка создания FROG: %v", err)
	}

	// Тест с неправильным размером блока
	wrongSizePlaintext := []byte("Short")
	_, err = frog.EncryptBlock(wrongSizePlaintext)
	if err == nil {
		t.Errorf("Ожидалась ошибка при шифровании блока неправильного размера")
	}

	wrongSizeCiphertext := []byte("Short")
	_, err = frog.DecryptBlock(wrongSizeCiphertext)
	if err == nil {
		t.Errorf("Ожидалась ошибка при дешифровании блока неправильного размера")
	}
}

func TestFROGEmptyKey(t *testing.T) {
	_, err := New([]byte{})
	if err == nil {
		t.Errorf("Ожидалась ошибка при создании FROG с пустым ключом")
	}
}

func BenchmarkFROGEncrypt(b *testing.B) {
	key := make([]byte, 16)
	plaintext := make([]byte, BlockSize)

	frog, _ := New(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = frog.EncryptBlock(plaintext)
	}
}

func BenchmarkFROGDecrypt(b *testing.B) {
	key := make([]byte, 16)
	ciphertext := make([]byte, BlockSize)

	frog, _ := New(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = frog.DecryptBlock(ciphertext)
	}
}
