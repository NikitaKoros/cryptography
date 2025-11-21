package deal

import (
	"crypto/sha256"
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

// DEALKeyExpander реализация расширения ключа для DEAL
type DEALKeyExpander struct {
	keySize   int // Размер ключа в байтах
	blockSize int // Размер блока в байтах (16, 24, 32)
	rounds    int // Количество раундов
}

// NewDEALKeyExpander создаёт новый экспандер ключей для DEAL
func NewDEALKeyExpander(keySize, blockSize int) *DEALKeyExpander {
	// Определяем количество раундов в зависимости от размера ключа
	rounds := 6
	if keySize == 16 { // DEAL-128
		rounds = 6
	} else if keySize == 24 { // DEAL-192
		rounds = 6
	} else if keySize == 32 { // DEAL-256
		rounds = 8
	}

	return &DEALKeyExpander{
		keySize:   keySize,
		blockSize: blockSize,
		rounds:    rounds,
	}
}

// ExpandKey расширяет ключ для DEAL с улучшенной схемой
func (ke *DEALKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != ke.keySize {
		return nil, errors.New("invalid key size for DEAL")
	}

	if ke.keySize != 16 && ke.keySize != 24 && ke.keySize != 32 {
		return nil, errors.New("unsupported key size")
	}

	subkeys := make([][]byte, ke.rounds)

	// Используем SHA-256 для более надежной генерации подключей
	baseHash := sha256.Sum256(key)

	for i := 0; i < ke.rounds; i++ {
		subkey := make([]byte, 8)

		// Генерируем подключ на основе базового хеша и номера раунда
		roundData := make([]byte, len(baseHash)+1)
		copy(roundData, baseHash[:])
		roundData[len(baseHash)] = byte(i + 1)

		roundHash := sha256.Sum256(roundData)

		// Берем первые 8 байт хеша для подключа
		copy(subkey, roundHash[:8])

		// Добавляем зависимость от ключа
		for j := 0; j < 8; j++ {
			keyIndex := (i*8 + j) % len(key)
			subkey[j] ^= key[keyIndex]
		}

		subkeys[i] = subkey
	}

	return subkeys, nil
}

// Проверяем, что DEALKeyExpander реализует интерфейс KeyExpander
var _ core.KeyExpander = (*DEALKeyExpander)(nil)
