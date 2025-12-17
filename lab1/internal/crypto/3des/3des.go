package threedes

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

// TripleDES реализует Triple DES в режиме EDE3 (Encrypt-Decrypt-Encrypt с 3 ключами)
// Использует схему: Encrypt(K1) → Decrypt(K2) → Encrypt(K3)
// Эффективная длина ключа: 168 бит (3×56)
type TripleDES struct {
	des1 core.SymmetricCipher // Первый DES для шифрования с K1
	des2 core.SymmetricCipher // Второй DES для дешифрования с K2
	des3 core.SymmetricCipher // Третий DES для шифрования с K3
}

// NewTripleDES создает новый экземпляр Triple DES
// Принимает три независимых экземпляра DES шифра
func NewTripleDES(des1, des2, des3 core.SymmetricCipher) *TripleDES {
	return &TripleDES{
		des1: des1,
		des2: des2,
		des3: des3,
	}
}

// SetEncryptionKey устанавливает ключ шифрования для Triple DES
// Ожидает 24 байта (192 бита): 8 байт для K1, 8 байт для K2, 8 байт для K3
func (t *TripleDES) SetEncryptionKey(key []byte) error {
	if len(key) != 24 {
		return errors.New("Triple DES key must be exactly 24 bytes (192 bits)")
	}

	// Разделяем ключ на три части по 8 байт
	key1 := key[0:8]
	key2 := key[8:16]
	key3 := key[16:24]

	// Устанавливаем ключи для шифрования
	// des1: шифрование с K1
	if err := t.des1.SetEncryptionKey(key1); err != nil {
		return err
	}

	// des2: дешифрование с K2 (для EDE схемы)
	if err := t.des2.SetDecryptionKey(key2); err != nil {
		return err
	}

	// des3: шифрование с K3
	if err := t.des3.SetEncryptionKey(key3); err != nil {
		return err
	}

	return nil
}

// SetDecryptionKey устанавливает ключ дешифрования для Triple DES
// Ожидает 24 байта (192 бита): 8 байт для K1, 8 байт для K2, 8 байт для K3
func (t *TripleDES) SetDecryptionKey(key []byte) error {
	if len(key) != 24 {
		return errors.New("Triple DES key must be exactly 24 bytes (192 bits)")
	}

	// Разделяем ключ на три части по 8 байт
	key1 := key[0:8]
	key2 := key[8:16]
	key3 := key[16:24]

	// Устанавливаем ключи для дешифрования (обратный порядок)
	// des3: дешифрование с K3
	if err := t.des3.SetDecryptionKey(key3); err != nil {
		return err
	}

	// des2: шифрование с K2 (обратная операция для EDE)
	if err := t.des2.SetEncryptionKey(key2); err != nil {
		return err
	}

	// des1: дешифрование с K1
	if err := t.des1.SetDecryptionKey(key1); err != nil {
		return err
	}

	return nil
}

// EncryptBlock шифрует один 64-битный блок
// Схема: Encrypt(K1) → Decrypt(K2) → Encrypt(K3)
func (t *TripleDES) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("Triple DES block must be exactly 8 bytes")
	}

	// Первый этап: Encrypt с K1
	encrypted1, err := t.des1.EncryptBlock(block)
	if err != nil {
		return nil, err
	}

	// Второй этап: Decrypt с K2
	decrypted2, err := t.des2.DecryptBlock(encrypted1)
	if err != nil {
		return nil, err
	}

	// Третий этап: Encrypt с K3
	encrypted3, err := t.des3.EncryptBlock(decrypted2)
	if err != nil {
		return nil, err
	}

	return encrypted3, nil
}

// DecryptBlock дешифрует один 64-битный блок
// Схема: Decrypt(K3) → Encrypt(K2) → Decrypt(K1)
func (t *TripleDES) DecryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("Triple DES block must be exactly 8 bytes")
	}

	// Первый этап: Decrypt с K3
	decrypted3, err := t.des3.DecryptBlock(block)
	if err != nil {
		return nil, err
	}

	// Второй этап: Encrypt с K2
	encrypted2, err := t.des2.EncryptBlock(decrypted3)
	if err != nil {
		return nil, err
	}

	// Третий этап: Decrypt с K1
	decrypted1, err := t.des1.DecryptBlock(encrypted2)
	if err != nil {
		return nil, err
	}

	return decrypted1, nil
}

// BlockSize возвращает размер блока в байтах (8 байт для Triple DES)
func (t *TripleDES) BlockSize() int {
	return 8
}

// Проверка соответствия интерфейсу SymmetricCipher
var _ core.SymmetricCipher = (*TripleDES)(nil)
