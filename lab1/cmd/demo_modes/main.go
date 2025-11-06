package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func main() {
	// Создаем DES cipher
	desCipher := des.NewDES()
	
	// Ключ DES (8 байт)
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	
	// Устанавливаем ключ
	if err := desCipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Генерируем случайный IV для режимов, которые его требуют
	iv := make([]byte, 8) // 8 байт для DES
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("IV generation failed: %v", err)
	}

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