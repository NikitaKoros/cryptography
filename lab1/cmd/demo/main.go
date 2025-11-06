package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func main() {
	desCipher := des.NewDES()

	// Ключ DES (8 байт)
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}

	// Блок для шифрования (8 байт)
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	fmt.Printf("Original:  %x\n", plaintext)

	// Устанавливаем ключ (обрабатываем ошибку)
	if err := desCipher.SetEncryptionKey(key); err != nil {
		log.Fatalf("SetEncryptionKey failed: %v", err)
	}

	// Шифрование (обрабатываем ошибку)
	ciphertext, err := desCipher.EncryptBlock(plaintext)
	if err != nil {
		log.Fatalf("EncryptBlock failed: %v", err)
	}
	fmt.Printf("Encrypted: %x\n", ciphertext)

	// Дешифрование (обрабатываем ошибку)
	decrypted, err := desCipher.DecryptBlock(ciphertext)
	if err != nil {
		log.Fatalf("DecryptBlock failed: %v", err)
	}
	fmt.Printf("Decrypted: %x\n", decrypted)

	// Проверка
	fmt.Printf("Match: %t\n", bytes.Equal(plaintext, decrypted))
}
