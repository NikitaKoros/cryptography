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
// В DEAL раундовая функция F обрабатывает половину блока (64 бита) через DES
func (da *DESAdapter) EncryptRound(block []byte, roundKey []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, errors.New("DEAL block must be 16 bytes")
	}

	// Разбиваем блок на две части по 64 бита (8 байт)
	left := block[:8]
	right := block[8:]

	// Устанавливаем ключ для DES
	if err := da.des.SetEncryptionKey(roundKey); err != nil {
		return nil, err
	}

	// Шифруем правую часть с помощью DES - это и есть функция F
	fResult, err := da.des.EncryptBlock(right)
	if err != nil {
		return nil, err
	}

	// XOR левой части с результатом функции F
	newLeft := xorBytes(left, fResult)

	// Собираем новый блок: newLeft + right (для следующего раунда)
	result := make([]byte, 16)
	copy(result[:8], newLeft)
	copy(result[8:], right)

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
