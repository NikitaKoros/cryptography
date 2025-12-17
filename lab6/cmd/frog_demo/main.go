package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/NikitaKoros/cryptography/lab6/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab6/internal/frog"
	"github.com/NikitaKoros/cryptography/lab6/internal/gf256"
)

func main() {
	fmt.Println("=== Полное тестирование FROG ===\n")

	key := []byte("TestKey123456789")
	frogCipher, err := frog.New(key)
	if err != nil {
		log.Fatalf("Ошибка создания FROG: %v", err)
	}

	fmt.Printf("Ключ: %s (%x)\n\n", string(key), key)

	// Базовое тестирование блока
	fmt.Println("--- Базовое шифрование блока ---")
	plaintextBlock := []byte("0123456789ABCDEF")
	fmt.Printf("Original block:  %x\n", plaintextBlock)

	ciphertextBlock, err := frogCipher.EncryptBlock(plaintextBlock)
	if err != nil {
		log.Fatalf("EncryptBlock failed: %v", err)
	}
	fmt.Printf("Encrypted block: %x\n", ciphertextBlock)

	decryptedBlock, err := frogCipher.DecryptBlock(ciphertextBlock)
	if err != nil {
		log.Fatalf("DecryptBlock failed: %v", err)
	}
	fmt.Printf("Decrypted block: %x\n", decryptedBlock)
	fmt.Printf("Match: %t\n\n", bytes.Equal(plaintextBlock, decryptedBlock))

	// Генерируем IV
	iv := make([]byte, frog.BlockSize)
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

	// Создаем данные размером 1 КБ для более точного замера времени
	plaintext := make([]byte, 8*1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	successCount := 0
	failCount := 0

	for _, mode := range modes {
		fmt.Println()
		for _, padding := range paddings {
			fmt.Printf("Testing %v + %v... ", mode, padding)

			ctx := core.NewCipherContext(frogCipher, mode, padding, iv)

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
				fmt.Printf("Decryption failed: %v\n", err)
				failCount++
				continue
			}

			if bytes.Equal(plaintext, decrypted) {
				fmt.Printf("(enc: %v, dec: %v)\n", encTime.Round(time.Microsecond), decTime.Round(time.Microsecond))
				successCount++
			} else {
				fmt.Println("Content mismatch")
				failCount++
			}
		}
	}

	fmt.Printf("\n=== Результаты тестирования режимов ===\n")
	fmt.Printf("Успешно: %d/%d\n", successCount, successCount+failCount)
	fmt.Printf("Неудачно: %d/%d\n\n", failCount, successCount+failCount)

	fmt.Println("=== Тестирование файловых операций ===\n")

	testFiles := []string{
		"test.txt",
		"large_test.txt",
		"5062318-uhd_2560_1440_25fps.mp4",
	}

	for _, filename := range testFiles {
		inputPath := filepath.Join("./test_files", filename)

		if _, err := os.Stat(inputPath); os.IsNotExist(err) {
			fmt.Printf("⊘ Файл %s не найден, пропускаем\n", filename)
			continue
		}

		fmt.Printf("\n--- Тестирование: %s ---\n", filename)

		info, err := os.Stat(inputPath)
		if err != nil {
			log.Printf("Ошибка получения информации о файле: %v", err)
			continue
		}
		fmt.Printf("Размер файла: %d байт (%.2f MB)\n", info.Size(), float64(info.Size())/1024/1024)

		testModes := []struct {
			mode    core.CipherMode
			padding core.PaddingMode
		}{
			{core.ECB, core.PadPKCS7},
			{core.CBC, core.PadISO10126},
			{core.CTR, core.PadANSIX923},
		}

		for _, tm := range testModes {
			fmt.Printf("  Режим: %v + %v... ", tm.mode, tm.padding)

			ext := filepath.Ext(filename)
			if len(ext) > 0 {
				ext = ext[1:]
			}

			encryptedFile := filepath.Join("./test_files", fmt.Sprintf("%s_encrypted.bin", filename))
			decryptedFile := filepath.Join("./test_files", fmt.Sprintf("%s_decrypted.%s", filename, ext))

			ctx := core.NewCipherContext(frogCipher, tm.mode, tm.padding, iv)

			startEnc := time.Now()
			if err := ctx.EncryptFile(inputPath, encryptedFile); err != nil {
				fmt.Printf("✗ Ошибка шифрования: %v\n", err)
				continue
			}
			encryptTime := time.Since(startEnc)

			startDec := time.Now()
			if err := ctx.DecryptFile(encryptedFile, decryptedFile); err != nil {
				fmt.Printf("✗ Ошибка дешифрования: %v\n", err)
				os.Remove(encryptedFile)
				continue
			}
			decryptTime := time.Since(startDec)

			origHash, err := HashFileSHA256(inputPath)
			if err != nil {
				fmt.Printf("✗ Ошибка хеширования оригинала: %v\n", err)
				os.Remove(encryptedFile)
				os.Remove(decryptedFile)
				continue
			}

			decHash, err := HashFileSHA256(decryptedFile)
			if err != nil {
				fmt.Printf("✗ Ошибка хеширования расшифрованного: %v\n", err)
				os.Remove(encryptedFile)
				os.Remove(decryptedFile)
				continue
			}

			if origHash == decHash {
				fmt.Printf("✓ (шифрование: %v, дешифрование: %v)\n", encryptTime.Round(time.Millisecond), decryptTime.Round(time.Millisecond))
			} else {
				fmt.Println("✗ Хеши не совпадают")
			}

			os.Remove(encryptedFile)
			os.Remove(decryptedFile)
		}
	}

	fmt.Println("\n=== Неприводимые полиномы GF(2^8) ===\n")
	polynomials := gf256.GetAllIrreduciblePolynomials()
	fmt.Printf("Всего найдено неприводимых полиномов: %d\n", len(polynomials))
	fmt.Printf("Первые 5 полиномов:\n")
	for i := 0; i < 5 && i < len(polynomials); i++ {
		fmt.Printf("  %d. 0x%02X - %s\n", i+1, polynomials[i], gf256.PolyToString(polynomials[i]))
	}

	fmt.Println("\n=== Тестирование завершено ===")
}

func HashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
