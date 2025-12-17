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

	"github.com/NikitaKoros/cryptography/lab3/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab3/internal/crypto/rijndael"
	"github.com/NikitaKoros/cryptography/lab3/internal/gf256"
)

func main() {
	fmt.Println("=== Демонстрация работы с GF(2^8) ===")
	fmt.Println()

	// Получаем все неприводимые полиномы степени 8
	irreduciblePolys := gf256.GetAllIrreduciblePolynomials()
	fmt.Printf("Найдено неприводимых полиномов степени 8: %d\n", len(irreduciblePolys))
	fmt.Println("Первые 10 неприводимых полиномов:")
	for i := 0; i < 10 && i < len(irreduciblePolys); i++ {
		fmt.Printf("  %d. 0x%02X = %s\n", i+1, irreduciblePolys[i], gf256.PolyToString(irreduciblePolys[i]))
	}
	fmt.Println()

	// Используем стандартный полином AES для демонстрации
	modulus := byte(0x1B) // x^8 + x^4 + x^3 + x + 1
	fmt.Printf("Используемый модуль: 0x%02X = %s\n", modulus, gf256.PolyToString(modulus))
	fmt.Printf("Является неприводимым: %t\n\n", gf256.IsIrreducible(modulus))

	gf, err := gf256.NewGF256(modulus)
	if err != nil {
		log.Fatalf("Ошибка создания GF(2^8): %v", err)
	}

	// Демонстрация операций в GF(2^8)
	a := byte(0x53)
	b := byte(0xCA)

	fmt.Println("--- Операции в GF(2^8) ---")
	fmt.Printf("a = 0x%02X, b = 0x%02X\n", a, b)
	fmt.Printf("a + b = 0x%02X\n", gf256.Add(a, b))
	fmt.Printf("a * b = 0x%02X\n", gf.Multiply(a, b))

	invA, err := gf.Inverse(a)
	if err != nil {
		log.Printf("Ошибка вычисления обратного элемента: %v", err)
	} else {
		fmt.Printf("a^(-1) = 0x%02X\n", invA)
		fmt.Printf("a * a^(-1) = 0x%02X (должно быть 0x01)\n", gf.Multiply(a, invA))
	}
	fmt.Println()

	// Демонстрация факторизации полинома
	fmt.Println("--- Факторизация полинома ---")
	poly := uint64(0b110110110) // x^8 + x^7 + x^5 + x^4 + x^2 + x
	fmt.Printf("Полином: 0b%b\n", poly)
	factors := gf256.FactorPolynomial(poly)
	fmt.Printf("Множители: %v\n\n", factors)

	fmt.Println("=== Демонстрация алгоритма Rijndael ===")
	fmt.Println()

	// Тестирование различных размеров блоков и ключей
	blockSizes := []int{16, 24, 32}  // 128, 192, 256 бит
	keySizes := []int{16, 24, 32}    // 128, 192, 256 бит
	testModuli := []byte{0x1B, 0x11B & 0xFF, 0x165 & 0xFF} // Различные неприводимые полиномы

	// Выбираем один модуль для основных тестов
	selectedModulus := testModuli[0]

	for _, blockSize := range blockSizes {
		for _, keySize := range keySizes {
			fmt.Printf("\n--- Rijndael-%d с ключом %d бит ---\n", blockSize*8, keySize*8)

			cipher, err := rijndael.NewRijndael(blockSize, keySize, selectedModulus)
			if err != nil {
				log.Printf("Ошибка создания Rijndael: %v", err)
				continue
			}

			// Генерируем случайный ключ
			key := make([]byte, keySize)
			if _, err := rand.Read(key); err != nil {
				log.Printf("Ошибка генерации ключа: %v", err)
				continue
			}

			if err := cipher.SetEncryptionKey(key); err != nil {
				log.Printf("Ошибка установки ключа шифрования: %v", err)
				continue
			}

			if err := cipher.SetDecryptionKey(key); err != nil {
				log.Printf("Ошибка установки ключа дешифрования: %v", err)
				continue
			}

			// Генерируем случайный блок данных
			plaintext := make([]byte, blockSize)
			if _, err := rand.Read(plaintext); err != nil {
				log.Printf("Ошибка генерации данных: %v", err)
				continue
			}

			fmt.Printf("Plaintext:  %x\n", plaintext)

			// Шифруем
			ciphertext, err := cipher.EncryptBlock(plaintext)
			if err != nil {
				log.Printf("Ошибка шифрования: %v", err)
				continue
			}
			fmt.Printf("Ciphertext: %x\n", ciphertext)

			// Дешифруем
			decrypted, err := cipher.DecryptBlock(ciphertext)
			if err != nil {
				log.Printf("Ошибка дешифрования: %v", err)
				continue
			}
			fmt.Printf("Decrypted:  %x\n", decrypted)
			fmt.Printf("Совпадение: %t\n", bytes.Equal(plaintext, decrypted))
		}
	}

	fmt.Println("\n=== Тестирование режимов шифрования ===")
	fmt.Println()

	// Создаем Rijndael-128 с ключом 128 бит для тестов режимов
	cipher, err := rijndael.NewRijndael(16, 16, selectedModulus)
	if err != nil {
		log.Fatalf("Ошибка создания Rijndael: %v", err)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Ошибка генерации ключа: %v", err)
	}

	if err := cipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("Ошибка установки ключа шифрования: %v", err)
	}

	if err := cipher.SetDecryptionKey(key); err != nil {
		log.Fatalf("Ошибка установки ключа дешифрования: %v", err)
	}

	// IV для режимов, требующих его
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("Ошибка генерации IV: %v", err)
	}

	modes := []core.CipherMode{
		core.ECB,
		core.CBC,
		core.CFB,
		core.OFB,
		core.CTR,
	}

	paddingModes := []core.PaddingMode{
		core.PadPKCS7,
		core.PadANSIX923,
		core.PadISO10126,
	}

	testData := []byte("Hello, Rijndael! This is a test message for encryption with various modes and padding schemes.")

	for _, mode := range modes {
		for _, padding := range paddingModes {
			fmt.Printf("\nРежим: %v, Паддинг: %v\n", mode, padding)

			ctx := core.NewCipherContext(cipher, mode, padding, iv)

			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				log.Printf("Ошибка шифрования: %v", err)
				continue
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				log.Printf("Ошибка дешифрования: %v", err)
				continue
			}

			match := bytes.Equal(testData, decrypted)
			fmt.Printf("Зашифровано: %d байт, Совпадение: %t\n", len(encrypted), match)
			if !match {
				fmt.Printf("Ожидалось: %s\n", testData)
				fmt.Printf("Получено:  %s\n", decrypted)
			}
		}
	}

	fmt.Println("\n=== Тестирование шифрования файлов ===")
	fmt.Println()

	// Создаем тестовый файл
	testFileData := []byte("This is a test file for encryption. It contains some data that will be encrypted and then decrypted using Rijndael cipher.")
	testInputFile := "./test_files/test_input.txt"
	testEncryptedFile := "./test_files/test_encrypted.bin"
	testDecryptedFile := "./test_files/test_decrypted.txt"

	if err := os.WriteFile(testInputFile, testFileData, 0644); err != nil {
		log.Printf("Ошибка создания тестового файла: %v", err)
	} else {
		ctx := core.NewCipherContext(cipher, core.CBC, core.PadPKCS7, iv)

		fmt.Println("Шифрование файла...")
		if err := ctx.EncryptFile(testInputFile, testEncryptedFile); err != nil {
			log.Printf("Ошибка шифрования файла: %v", err)
		} else {
			fmt.Println("Файл зашифрован успешно")

			fmt.Println("Дешифрование файла...")
			if err := ctx.DecryptFile(testEncryptedFile, testDecryptedFile); err != nil {
				log.Printf("Ошибка дешифрования файла: %v", err)
			} else {
				decryptedData, _ := os.ReadFile(testDecryptedFile)
				fmt.Printf("Файл дешифрован успешно\n")
				fmt.Printf("Совпадение: %t\n", bytes.Equal(testFileData, decryptedData))
			}
		}
	}

	fmt.Println("\n=== Тестирование с различными неприводимыми полиномами ===")
	fmt.Println()

	// Берем первые 5 неприводимых полиномов для тестирования
	testPolys := irreduciblePolys[:5]

	for i, poly := range testPolys {
		fmt.Printf("\n--- Тест %d: Модуль 0x%02X ---\n", i+1, poly)

		testCipher, err := rijndael.NewRijndael(16, 16, poly)
		if err != nil {
			log.Printf("Ошибка создания Rijndael: %v", err)
			continue
		}

		testKey := make([]byte, 16)
		if _, err := rand.Read(testKey); err != nil {
			log.Printf("Ошибка генерации ключа: %v", err)
			continue
		}

		if err := testCipher.SetEncryptionKey(testKey); err != nil {
			log.Printf("Ошибка установки ключа шифрования: %v", err)
			continue
		}

		if err := testCipher.SetDecryptionKey(testKey); err != nil {
			log.Printf("Ошибка установки ключа дешифрования: %v", err)
			continue
		}

		testPlaintext := []byte("Test with different modulus!")
		testIV := make([]byte, 16)
		rand.Read(testIV)

		testCtx := core.NewCipherContext(testCipher, core.CBC, core.PadPKCS7, testIV)

		encrypted, err := testCtx.Encrypt(testPlaintext)
		if err != nil {
			log.Printf("Ошибка шифрования: %v", err)
			continue
		}

		decrypted, err := testCtx.Decrypt(encrypted)
		if err != nil {
			log.Printf("Ошибка дешифрования: %v", err)
			continue
		}

		fmt.Printf("Plaintext:  %s\n", testPlaintext)
		fmt.Printf("Ciphertext: %x\n", encrypted[:16])
		fmt.Printf("Совпадение: %t\n", bytes.Equal(testPlaintext, decrypted))
	}

	fmt.Println("\n=== Тестирование шифрования изображения ===")
	fmt.Println()

	// Проверяем, есть ли тестовое изображение
	imageFiles := []string{
		"./test_files/test_image.jpg",
		"./test_files/test_image.png",
	}

	var imageFile string
	for _, file := range imageFiles {
		if _, err := os.Stat(file); err == nil {
			imageFile = file
			break
		}
	}

	if imageFile != "" {
		fmt.Printf("Найдено изображение: %s\n", imageFile)
		encryptedImage := "./test_files/encrypted_image.bin"
		decryptedImage := "./test_files/decrypted_image" + imageFile[len(imageFile)-4:]

		imageCipher, _ := rijndael.NewRijndael(16, 16, selectedModulus)
		imageKey := make([]byte, 16)
		rand.Read(imageKey)
		imageCipher.SetEncryptionKey(imageKey)
		imageCipher.SetDecryptionKey(imageKey)

		imageIV := make([]byte, 16)
		rand.Read(imageIV)

		imageCtx := core.NewCipherContext(imageCipher, core.CBC, core.PadPKCS7, imageIV)

		fmt.Println("Шифрование изображения...")
		if err := imageCtx.EncryptFile(imageFile, encryptedImage); err != nil {
			log.Printf("Ошибка шифрования изображения: %v", err)
		} else {
			fmt.Println("Изображение зашифровано")

			fmt.Println("Дешифрование изображения...")
			if err := imageCtx.DecryptFile(encryptedImage, decryptedImage); err != nil {
				log.Printf("Ошибка дешифрования изображения: %v", err)
			} else {
				origHash, _ := HashFileSHA256(imageFile)
				decHash, _ := HashFileSHA256(decryptedImage)
				fmt.Printf("Изображение дешифровано\n")
				fmt.Printf("Хеш-суммы совпадают: %t\n", origHash == decHash)
			}
		}
	} else {
		fmt.Println("Тестовое изображение не найдено. Поместите изображение в ./test_files/test_image.jpg или .png")
	}

	fmt.Println("\n=== Завершение демонстрации ===")
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
