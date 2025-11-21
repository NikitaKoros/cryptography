package main

import (
	"fmt"
	"log"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/deal"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

func main() {
	desCipher := des.NewDES()

	dealCipher := deal.NewDEAL128(desCipher)

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	if err := dealCipher.SetEncryptionKey(key); err != nil {
		log.Fatal("SetEncryptionKey error:", err)
	}

	block := make([]byte, 16)
	for i := range block {
		block[i] = byte(i + 10)
	}

	fmt.Printf("Original block: %x\n", block)

	encrypted, err := dealCipher.EncryptBlock(block)
	if err != nil {
		log.Fatal("EncryptBlock error:", err)
	}

	fmt.Printf("Encrypted: %x\n", encrypted)

	decrypted, err := dealCipher.DecryptBlock(encrypted)
	if err != nil {
		log.Fatal("DecryptBlock error:", err)
	}

	fmt.Printf("Decrypted: %x\n", decrypted)

	fmt.Printf("Match: %t\n", string(block) == string(decrypted))
}
