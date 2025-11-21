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

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des/feistel"
)

func main() {
	fmt.Println("=== DES на базе универсальной сети Фейстеля ===")
	fmt.Println()

	desCipher := feistel.NewDESFeistel()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}

	if err := desCipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("SetEncryptionKey failed: %v", err)
	}

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

	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("IV generation failed: %v", err)
	}

	fmt.Println("=== Тестирование режимов шифрования с Feistel DES ===")
	fmt.Println()

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
	plaintext := []byte("Hello, DES! This is a test message for encryption.")

	for _, mode := range modes {
		fmt.Printf("\n=== Testing %v ===\n", mode)

		ctx := core.NewCipherContext(desCipher, mode, padding, iv)

		ciphertext, err := ctx.Encrypt(plaintext)
		if err != nil {
			log.Printf("Encryption failed for %v: %v", mode, err)
			continue
		}
		fmt.Printf("Encrypted (%d bytes): %x...\n", len(ciphertext), ciphertext[:16])

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
		ctx := core.NewCipherContext(desCipher, core.ECB, padMode, iv)

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

	testData := []byte("This is a test file for encryption. It contains some data that will be encrypted and then decrypted.")
	if err := os.WriteFile("test_input.txt", testData, 0644); err != nil {
		log.Printf("Failed to create test file: %v", err)
	} else {
		ctx := core.NewCipherContext(desCipher, core.CBC, core.PadPKCS7, iv)

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

	fmt.Printf("\n=== Testing stream encryption ===\n")

	//var filename = "large_test.txt"
	var filename = "5062318-uhd_2560_1440_25fps.mp4"

	inputPath := "./test_files/" + filename

	// largeData := bytes.Repeat([]byte("Large file data for streaming encryption test. "), 2500000) // ~110.5 MB
	// if err := os.WriteFile(inputPath, largeData, 0644); err != nil {
	// 	log.Printf("Failed to create large test file: %v", err)
	// 	os.Exit(1)
	// }

	ext := filepath.Ext(filename)
	if len(ext) > 0 {
		ext = ext[1:]
	}

	decryptedFile := fmt.Sprintf("large_decrypted.%s", ext)

	outputPath := "./test_files/" + decryptedFile

	ctx := core.NewCipherContext(desCipher, core.ECB, core.PadPKCS7, iv)

	info, err := os.Stat(inputPath)
	if err != nil {
		log.Printf("Failed to get large file size")
		os.Exit(1)
	}
	size := info.Size()
	fmt.Printf("Encrypting large file (%d bytes)...\n", size)

	if err := ctx.EncryptFile(inputPath, "./test_files/large_encrypted.bin"); err != nil {
		log.Printf("Large file encryption failed: %v", err)
	} else {
		fmt.Println("Large file encrypted successfully (using streaming)")

		if err := ctx.DecryptFile("./test_files/large_encrypted.bin", outputPath); err != nil {
			log.Printf("Large file decryption failed: %v", err)
		} else {

			origHash, err := HashFileSHA256(inputPath)
			if err != nil {
				log.Printf("Failed to hash original file: %v", err)
				os.Exit(1)
			}

			decHash, err := HashFileSHA256(outputPath)
			if err != nil {
				log.Printf("Failed to hash decrypted file: %v", err)
				os.Exit(1)
			}

			fmt.Println("Large file decrypted successfully")
			fmt.Printf("Match: %t\n", origHash == decHash)

			// os.Remove(inputPath)
			// os.Remove("./test_files/large_encrypted.bin")
			// os.Remove(outputPath)
		}
	}
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
