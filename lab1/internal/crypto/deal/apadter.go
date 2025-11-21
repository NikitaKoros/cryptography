package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

// DESAdapter адаптер для использования DES в качестве раундовой функции F
type DESAdapter struct {
	des core.SymmetricCipher
}

// NewDESAdapter создаёт новый адаптер для DES
func NewDESAdapter(des core.SymmetricCipher) *DESAdapter {
	return &DESAdapter{
		des: des,
	}
}

// EncryptRound реализует раундовую функцию F для DEAL
func (da *DESAdapter) EncryptRound(block []byte, roundKey []byte) ([]byte, error) {
	blockSize := len(block)
	if blockSize < 16 || blockSize > 48 || blockSize%8 != 0 {
		return nil, errors.New("invalid block size for DES adapter")
	}

	halfSize := blockSize / 2

	// Разбиваем блок на две части
	left := block[:halfSize]
	right := block[halfSize:]

	// Устанавливаем ключ для DES
	if err := da.des.SetEncryptionKey(roundKey); err != nil {
		return nil, err
	}

	// Обрабатываем правую часть в зависимости от размера
	var fResult []byte
	var err error

	if halfSize == 8 {
		// Стандартный случай: правая половина 8 байт
		fResult, err = da.des.EncryptBlock(right)
		if err != nil {
			return nil, err
		}
	} else {
		// Для больших блоков: шифруем каждую 8-байтную часть отдельно
		fResult = make([]byte, halfSize)
		numParts := halfSize / 8

		for part := 0; part < numParts; part++ {
			start := part * 8
			end := start + 8

			encryptedPart, err := da.des.EncryptBlock(right[start:end])
			if err != nil {
				return nil, err
			}

			copy(fResult[start:], encryptedPart)
		}
	}

	// XOR левой части с результатом функции F
	newLeft := xorBytes(left, fResult)

	// Собираем новый блок: newLeft + right (swap для следующего раунда)
	result := make([]byte, blockSize)
	copy(result[:halfSize], newLeft)
	copy(result[halfSize:], right)

	return result, nil
}

// xorBytes выполняет XOR двух байтовых срезов одинаковой длины
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xorBytes: slices must have equal length")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// Проверяем, что DESAdapter реализует интерфейс RoundEncrypter
var _ core.RoundEncrypter = (*DESAdapter)(nil)
