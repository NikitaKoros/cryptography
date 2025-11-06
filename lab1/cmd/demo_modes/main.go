package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des/feistel"
)

func main() {
	fmt.Println("=== DES на базе универсальной сети Фейстеля ===")
	fmt.Println()

	// Создаем DES cipher на базе Feistel Network
	desCipher := feistel.NewDESFeistel()

	// Ключ DES (8 байт)
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}

	// Устанавливаем ключ
	if err := desCipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Демонстрация базового шифрования блока
	fmt.Println("--- Базовое шифрование блока ---")
	plaintextBlock := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	fmt.Printf("Original block:  %x\n", plaintextBlock)

	ciphertextBlock, err := desCipher.EncryptBlock(plaintextBlock)
	if err != nil {
		log.Fatalf("EncryptBlock failed: %v", err)
	}
	fmt.Printf("Encrypted block: %x\n", ciphertextBlock)

	decryptedBlock, err := desCipher.DecryptBlock(ciphertextBlock)
	if err != nil {
		log.Fatalf("DecryptBlock failed: %v", err)
	}
	fmt.Printf("Decrypted block: %x\n", decryptedBlock)
	fmt.Printf("Match: %t\n\n", bytes.Equal(plaintextBlock, decryptedBlock))

	// Сравнение с оригинальной реализацией
	fmt.Println("--- Сравнение с оригинальной реализацией DES ---")
	desOriginal := des.NewDES()
	if err := desOriginal.SetEncryptionKey(key); err != nil {
		log.Fatalf("Original SetEncryptionKey failed: %v", err)
	}

	ciphertextOriginal, err := desOriginal.EncryptBlock(plaintextBlock)
	if err != nil {
		log.Fatalf("Original EncryptBlock failed: %v", err)
	}

	fmt.Printf("Original DES ciphertext: %x\n", ciphertextOriginal)
	fmt.Printf("Feistel DES ciphertext:  %x\n", ciphertextBlock)
	fmt.Printf("Results match: %t\n\n", bytes.Equal(ciphertextOriginal, ciphertextBlock))

	// Генерируем случайный IV для режимов, которые его требуют
	iv := make([]byte, 8) // 8 байт для DES
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("IV generation failed: %v", err)
	}

	fmt.Println("=== Тестирование режимов шифрования с Feistel DES ===")
	fmt.Println()

	// Тестируем разные режимы
	modes := []core.CipherMode{
		core.ECB,
		core.CBC,
		core.PCBC,
		core.CFB,
		core.OFB,
		core.CTR,
	}

	padding := core.PadPKCS7
	plaintext := []byte("Hello, DES! This is a test message for encryption.")

	for _, mode := range modes {
		fmt.Printf("\n=== Testing %v ===\n", mode)

		// Создаем контекст с выбранным режимом
		ctx := core.NewCipherContext(desCipher, mode, padding, iv)

		// Шифрование
		ciphertext, err := ctx.Encrypt(plaintext)
		if err != nil {
			log.Printf("Encryption failed for %v: %v", mode, err)
			continue
		}
		fmt.Printf("Encrypted (%d bytes): %x...\n", len(ciphertext), ciphertext[:16])

		// Дешифрование
		decrypted, err := ctx.Decrypt(ciphertext)
		if err != nil {
			log.Printf("Decryption failed for %v: %v", mode, err)
			continue
		}

		// Проверка
		match := bytes.Equal(plaintext, decrypted)
		fmt.Printf("Decrypted: %s\n", decrypted)
		fmt.Printf("Match: %t\n", match)

		// Тестируем асинхронную версию
		fmt.Printf("Testing async... ")
		decryptedCh, errCh := ctx.DecryptAsync(ciphertext)
		select {
		case asyncDecrypted := <-decryptedCh:
			asyncMatch := bytes.Equal(plaintext, asyncDecrypted)
			fmt.Printf("Async match: %t\n", asyncMatch)
		case err := <-errCh:
			fmt.Printf("Async error: %v\n", err)
		}
	}

	// Тестируем разные паддинги
	fmt.Printf("\n=== Testing different padding modes ===\n")
	testPaddings := []core.PaddingMode{
		core.PadZeros,
		core.PadPKCS7,
		core.PadANSIX923,
		core.PadISO10126,
	}

	for _, padMode := range testPaddings {
		fmt.Printf("\nPadding mode: %v\n", padMode)
		ctx := core.NewCipherContext(desCipher, core.CBC, padMode, iv)

		ciphertext, err := ctx.Encrypt(plaintext)
		if err != nil {
			log.Printf("Encryption failed: %v", err)
			continue
		}

		decrypted, err := ctx.Decrypt(ciphertext)
		if err != nil {
			log.Printf("Decryption failed: %v", err)
			continue
		}

		fmt.Printf("Success: %t\n", bytes.Equal(plaintext, decrypted))
	}
}
