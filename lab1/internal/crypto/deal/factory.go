package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

// DEALFactory фабрика для создания DEAL с различными параметрами
type DEALFactory struct{}

// NewDEALFactory создаёт новую фабрику DEAL
func NewDEALFactory() *DEALFactory {
	return &DEALFactory{}
}

// CreateDEAL создаёт DEAL шифр с указанными параметрами
func (df *DEALFactory) CreateDEAL(keySize, blockSize int) (core.SymmetricCipher, error) {
	// Проверяем допустимые размеры ключей
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("DEAL supports only 128, 192, or 256-bit keys")
	}

	// Проверяем, что размер блока четный (для разделения на две половины)
	if blockSize%2 != 0 {
		return nil, errors.New("DEAL block size must be even")
	}

	// Проверяем, что размер блока не меньше 16 байт
	if blockSize < 16 {
		return nil, errors.New("DEAL block size must be at least 16 bytes")
	}

	// Создаем базовый DES
	desCipher := des.NewDES()

	// Создаем DEAL с указанными параметрами
	switch {
	case keySize == 16 && blockSize == 16:
		return NewDEAL128(desCipher), nil
	case keySize == 24 && blockSize == 16:
		return NewDEAL192(desCipher), nil
	case keySize == 32 && blockSize == 16:
		return NewDEAL256(desCipher), nil
	default:
		return NewDEALWithCustomBlockSize(desCipher, keySize, blockSize), nil
	}
}

// CreateDEALWithCustomDES создаёт DEAL с пользовательской реализацией DES
func (df *DEALFactory) CreateDEALWithCustomDES(desCipher core.SymmetricCipher, keySize, blockSize int) (core.SymmetricCipher, error) {
	// Проверяем допустимые размеры ключей
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("DEAL supports only 128, 192, or 256-bit keys")
	}

	// Проверяем, что размер блока четный
	if blockSize%2 != 0 {
		return nil, errors.New("DEAL block size must be even")
	}

	// Проверяем, что размер блока не меньше 16 байт
	if blockSize < 16 {
		return nil, errors.New("DEAL block size must be at least 16 bytes")
	}

	return NewDEALWithCustomBlockSize(desCipher, keySize, blockSize), nil
}
