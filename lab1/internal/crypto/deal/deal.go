package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core/feistel"
)

// DESAdapter адаптирует DES для использования в качестве раундовой функции DEAL
type DESAdapter struct {
	desImpl core.SymmetricCipher
}

// NewDESAdapter создаёт адаптер для DES
func NewDESAdapter(desImpl core.SymmetricCipher) *DESAdapter {
	return &DESAdapter{
		desImpl: desImpl,
	}
}

// EncryptRound выполняет раундовое преобразование для DEAL
// block - 128-битный блок (16 байт), roundKey - 64-битный ключ (8 байт)
func (adapter *DESAdapter) EncryptRound(block []byte, roundKey []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, errors.New("DEAL block must be exactly 16 bytes")
	}
	if len(roundKey) != 8 {
		return nil, errors.New("DEAL round key must be exactly 8 bytes")
	}

	// Разбиваем 128-битный блок на левую и правую части (по 64 бита)
	left := make([]byte, 8)
	right := make([]byte, 8)
	copy(left, block[:8])
	copy(right, block[8:])

	// Устанавливаем раундовый ключ для DES
	if err := adapter.desImpl.SetEncryptionKey(roundKey); err != nil {
		return nil, err
	}

	// Шифруем правую часть с помощью DES
	encrypted, err := adapter.desImpl.EncryptBlock(right)
	if err != nil {
		return nil, err
	}

	// XOR левой части с зашифрованной правой частью
	newLeft := make([]byte, 8)
	for i := 0; i < 8; i++ {
		newLeft[i] = left[i] ^ encrypted[i]
	}

	// Формируем результат: новая левая часть становится правой,
	// старая правая часть становится левой
	result := make([]byte, 16)
	copy(result[:8], right)
	copy(result[8:], newLeft)

	return result, nil
}

// DEALKeySchedule реализует расширение ключа для DEAL
type DEALKeySchedule struct {
	desImpl core.SymmetricCipher
}

// NewDEALKeySchedule создаёт генератор ключей для DEAL
func NewDEALKeySchedule(desImpl core.SymmetricCipher) *DEALKeySchedule {
	return &DEALKeySchedule{
		desImpl: desImpl,
	}
}

// ExpandKey генерирует раундовые ключи для DEAL
// Для DEAL используется 6 раундов, каждый раунд требует 64-битный ключ
func (ks *DEALKeySchedule) ExpandKey(key []byte) ([][]byte, error) {
	// DEAL поддерживает ключи длиной 128, 192 или 256 бит
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("DEAL key must be 16, 24, or 32 bytes")
	}

	// Определяем количество раундов в зависимости от длины ключа
	var rounds int
	switch keyLen {
	case 16: // 128-bit key
		rounds = 6
	case 24: // 192-bit key
		rounds = 8
	default: // 256-bit key
		rounds = 8
	}

	roundKeys := make([][]byte, rounds)

	// Генерируем раундовые ключи
	for i := 0; i < rounds; i++ {
		// Используем различные части исходного ключа и генерируем подключи
		subkey := make([]byte, 8)

		// Простая схема генерации подключей из основного ключа
		for j := 0; j < 8; j++ {
			idx := (i*8 + j) % keyLen
			subkey[j] = key[idx] ^ byte(i)
		}

		// Дополнительное усложнение через DES
		if err := ks.desImpl.SetEncryptionKey(key[:8]); err != nil {
			return nil, err
		}

		encrypted, err := ks.desImpl.EncryptBlock(subkey)
		if err != nil {
			return nil, err
		}

		roundKeys[i] = encrypted
	}

	return roundKeys, nil
}

// DEAL реализация алгоритма DEAL на базе сети Фейстеля
type DEAL struct {
	feistelNetwork *feistel.FeistelNetwork
}

// NewDEAL создаёт новый экземпляр DEAL
// desImpl - реализация DES для использования в качестве раундовой функции
func NewDEAL(desImpl core.SymmetricCipher) *DEAL {
	// Создаём адаптер для DES
	adapter := NewDESAdapter(desImpl)

	// Создаём генератор ключей
	keySchedule := NewDEALKeySchedule(desImpl)

	// Создаём сеть Фейстеля с 6 раундами (для 128-битного ключа)
	feistelNetwork := feistel.NewFeistelNetwork(keySchedule, adapter, 6)

	return &DEAL{
		feistelNetwork: feistelNetwork,
	}
}

// SetEncryptionKey устанавливает ключ шифрования
func (d *DEAL) SetEncryptionKey(key []byte) error {
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return errors.New("DEAL key must be 16, 24, or 32 bytes")
	}
	return d.feistelNetwork.SetEncryptionKey(key)
}

// SetDecryptionKey устанавливает ключ дешифрования
func (d *DEAL) SetDecryptionKey(key []byte) error {
	return d.SetEncryptionKey(key)
}

// EncryptBlock шифрует один 128-битный блок
func (d *DEAL) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, errors.New("DEAL block must be exactly 16 bytes")
	}

	result, err := d.feistelNetwork.EncryptBlock(block)
	if err != nil {
		return nil, err
	}

	// Финальный swap левой и правой частей
	left := result[:8]
	right := result[8:]
	swapped := make([]byte, 16)
	copy(swapped[:8], right)
	copy(swapped[8:], left)

	return swapped, nil
}

// DecryptBlock дешифрует один 128-битный блок
func (d *DEAL) DecryptBlock(block []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, errors.New("DEAL block must be exactly 16 bytes")
	}

	result, err := d.feistelNetwork.DecryptBlock(block)
	if err != nil {
		return nil, err
	}

	// Финальный swap левой и правой частей
	left := result[:8]
	right := result[8:]
	swapped := make([]byte, 16)
	copy(swapped[:8], right)
	copy(swapped[8:], left)

	return swapped, nil
}

// Проверяем, что DEAL реализует интерфейс SymmetricCipher
var _ core.SymmetricCipher = (*DEAL)(nil)
