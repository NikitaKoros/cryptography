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
// В DEAL раундовая функция F обрабатывает правую половину блока через DES
// Но DES работает только с 8-байтными блоками, поэтому для больших блоков
// мы должны разбивать правую половину на 8-байтные части
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

	// Для DEAL функция F применяется только к правой части
	// Но если размер блока больше 16 байт, нам нужно адаптировать логику
	var fResult []byte
	var err error

	if halfSize == 8 {
		// Стандартный случай: правая половина 8 байт - шифруем целиком
		fResult, err = da.des.EncryptBlock(right)
		if err != nil {
			return nil, err
		}
	} else {
		// Для больших блоков: разбиваем правую половину на 8-байтные части
		// и шифруем каждую часть отдельно, затем объединяем
		fResult = make([]byte, halfSize)
		for i := 0; i < halfSize; i += 8 {
			end := i + 8
			if end > halfSize {
				end = halfSize
			}

			// Если часть меньше 8 байт, дополняем нулями
			part := make([]byte, 8)
			copy(part, right[i:end])

			encryptedPart, err := da.des.EncryptBlock(part)
			if err != nil {
				return nil, err
			}

			// Копируем только нужное количество байт обратно
			copy(fResult[i:], encryptedPart[:end-i])
		}
	}

	// XOR левой части с результатом функции F
	newLeft := xorBytes(left, fResult)

	// Собираем новый блок: newLeft + right (для следующего раунда)
	result := make([]byte, blockSize)
	copy(result[:halfSize], newLeft)
	copy(result[halfSize:], right)

	return result, nil
}

// xorBytes выполняет XOR двух байтовых срезов
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		minLen := len(a)
		if len(b) < minLen {
			minLen = len(b)
		}
		result := make([]byte, minLen)
		for i := 0; i < minLen; i++ {
			result[i] = a[i] ^ b[i]
		}
		return result
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// Проверяем, что DESAdapter реализует интерфейс RoundEncrypter
var _ core.RoundEncrypter = (*DESAdapter)(nil)
