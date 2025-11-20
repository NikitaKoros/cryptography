package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/deal"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des/feistel"
)

func main() {
	fmt.Println("=== DEAL на базе универсальной сети Фейстеля ===")
	fmt.Println()

	// Создаем DES для использования в DEAL
	desImpl := feistel.NewDESFeistel()

	// Создаем DEAL cipher на базе DES
	dealCipher := deal.NewDEAL(desImpl)

	// Ключ DEAL (16 байт = 128 бит)
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	// Устанавливаем ключ
	if err := dealCipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Демонстрация базового шифрования блока
	fmt.Println("--- Базовое шифрование блока ---")
	plaintextBlock := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	fmt.Printf("Original block:  %x\n", plaintextBlock)

	ciphertextBlock, err := dealCipher.EncryptBlock(plaintextBlock)
	if err != nil {
		log.Fatalf("EncryptBlock failed: %v", err)
	}
	fmt.Printf("Encrypted block: %x\n", ciphertextBlock)

	decryptedBlock, err := dealCipher.DecryptBlock(ciphertextBlock)
	if err != nil {
		log.Fatalf("DecryptBlock failed: %v", err)
	}
	fmt.Printf("Decrypted block: %x\n", decryptedBlock)
	fmt.Printf("Match: %t\n\n", bytes.Equal(plaintextBlock, decryptedBlock))

	// Генерируем случайный IV для режимов, которые его требуют
	iv := make([]byte, 16) // 16 байт для DEAL
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("IV generation failed: %v", err)
	}

	fmt.Println("=== Тестирование режимов шифрования с DEAL ===")
	fmt.Println()

	// Тестируем разные режимы
	modes := []core.CipherMode{
		core.ECB,
		core.CBC,
		core.PCBC,
		core.CFB,
		core.OFB,
		core.CTR,
		core.RandomDelta,
	}

	padding := core.PadPKCS7
	plaintext := []byte("Hello, DEAL! This is a test message for encryption with 128-bit blocks.")

	for _, mode := range modes {
		fmt.Printf("\n=== Testing %v ===\n", mode)

		ctx := core.NewCipherContext(dealCipher, mode, padding, iv)

		ciphertext, err := ctx.Encrypt(plaintext)
		if err != nil {
			log.Printf("Encryption failed for %v: %v", mode, err)
			continue
		}
		fmt.Printf("Encrypted (%d bytes): %x...\n", len(ciphertext), ciphertext[:min(32, len(ciphertext))])

		decrypted, err := ctx.Decrypt(ciphertext)
		if err != nil {
			log.Printf("Decryption failed for %v: %v", mode, err)
			continue
		}

		match := bytes.Equal(plaintext, decrypted)
		fmt.Printf("Decrypted: %s\n", decrypted)
		fmt.Printf("Match: %t\n", match)
	}

	fmt.Printf("\n=== Testing different padding modes ===\n")
	testPaddings := []core.PaddingMode{
		core.PadZeros,
		core.PadPKCS7,
		core.PadANSIX923,
		core.PadISO10126,
	}

	for _, padMode := range testPaddings {
		fmt.Printf("\nPadding mode: %v\n", padMode)
		ctx := core.NewCipherContext(dealCipher, core.ECB, padMode, iv)

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

	fmt.Printf("\n=== Testing file operations ===\n")

	testData := []byte("This is a test file for DEAL encryption. It contains some data that will be encrypted with 128-bit blocks and then decrypted.")
	if err := os.WriteFile("test_input.txt", testData, 0644); err != nil {
		log.Printf("Failed to create test file: %v", err)
	} else {
		ctx := core.NewCipherContext(dealCipher, core.CBC, core.PadPKCS7, iv)

		if err := ctx.EncryptFile("test_input.txt", "test_encrypted.bin"); err != nil {
			log.Printf("File encryption failed: %v", err)
		} else {
			fmt.Println("File encrypted successfully")

			if err := ctx.DecryptFile("test_encrypted.bin", "test_decrypted.txt"); err != nil {
				log.Printf("File decryption failed: %v", err)
			} else {
				decryptedData, _ := os.ReadFile("test_decrypted.txt")
				fmt.Printf("File decrypted successfully\n")
				fmt.Printf("Match: %t\n", bytes.Equal(testData, decryptedData))

				os.Remove("test_input.txt")
				os.Remove("test_encrypted.bin")
				os.Remove("test_decrypted.txt")
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
