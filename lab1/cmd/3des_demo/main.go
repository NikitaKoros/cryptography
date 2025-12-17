package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	threedes "github.com/NikitaKoros/cryptography/lab1/internal/crypto/3des"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func main() {
	fmt.Println("=== Полное тестирование Triple DES (DES-EDE3) ===\n")

	// Создаем три независимых экземпляра DES для Triple DES
	des1 := des.NewDES()
	des2 := des.NewDES()
	des3 := des.NewDES()

	// Создаем Triple DES cipher
	tripleDesCipher := threedes.NewTripleDES(des1, des2, des3)

	// Создаем ключ 24 байта (192 бита) для Triple DES-EDE3
	key := make([]byte, 24)
	for i := range key {
		key[i] = byte(i)
	}

	if err := tripleDesCipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("SetEncryptionKey error: %v", err)
	}

	fmt.Printf("Ключ: %x (24 байта)\n\n", key)

	// Базовое тестирование блока
	fmt.Println("--- Базовое шифрование блока ---")
	plaintextBlock := []byte("TestData")
	fmt.Printf("Original block:  %x\n", plaintextBlock)

	ciphertextBlock, err := tripleDesCipher.EncryptBlock(plaintextBlock)
	if err != nil {
		log.Fatalf("EncryptBlock failed: %v", err)
	}
	fmt.Printf("Encrypted block: %x\n", ciphertextBlock)

	decryptedBlock, err := tripleDesCipher.DecryptBlock(ciphertextBlock)
	if err != nil {
		log.Fatalf("DecryptBlock failed: %v", err)
	}
	fmt.Printf("Decrypted block: %x\n", decryptedBlock)
	fmt.Printf("Match: %t\n\n", bytes.Equal(plaintextBlock, decryptedBlock))

	// Генерируем IV
	iv := make([]byte, tripleDesCipher.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("Ошибка генерации IV: %v", err)
	}

	fmt.Println("=== Тестирование всех комбинаций режимов и паддингов ===\n")

	modes := []core.CipherMode{
		core.ECB,
		core.CBC,
		core.PCBC,
		core.CFB,
		core.OFB,
		core.CTR,
		core.RandomDelta,
	}

	paddings := []core.PaddingMode{
		core.PadZeros,
		core.PadPKCS7,
		core.PadANSIX923,
		core.PadISO10126,
	}

	// Создаем данные размером 8 МБ для более точного замера времени
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	successCount := 0
	failCount := 0

	for _, mode := range modes {
		fmt.Println()
		for _, padding := range paddings {
			fmt.Printf("Testing %v + %v... ", mode, padding)

			ctx := core.NewCipherContext(tripleDesCipher, mode, padding, iv)

			startEnc := time.Now()
			ciphertext, err := ctx.Encrypt(plaintext)
			encTime := time.Since(startEnc)

			if err != nil {
				fmt.Printf("✗ Encryption failed: %v\n", err)
				failCount++
				continue
			}

			startDec := time.Now()
			decrypted, err := ctx.Decrypt(ciphertext)
			decTime := time.Since(startDec)

			if err != nil {
				fmt.Printf("✗ Decryption failed: %v\n", err)
				failCount++
				continue
			}

			if bytes.Equal(plaintext, decrypted) {
				fmt.Printf("✓ (enc: %v, dec: %v)\n", encTime.Round(time.Microsecond), decTime.Round(time.Microsecond))
				successCount++
			} else {
				fmt.Println("✗ Content mismatch")
				failCount++
			}
		}
	}

	fmt.Printf("\n=== Результаты тестирования режимов ===\n")
	fmt.Printf("Успешно: %d/%d\n", successCount, successCount+failCount)
	fmt.Printf("Неудачно: %d/%d\n\n", failCount, successCount+failCount)

	fmt.Println("=== Тестирование завершено ===")
}
