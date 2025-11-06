package feistel

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

// FeistelNetwork универсальная реализация сети Фейстеля
type FeistelNetwork struct {
	keyExpander    core.KeyExpander
	roundEncrypter core.RoundEncrypter
	rounds         int
	encryptKeys    [][]byte
	decryptKeys    [][]byte
}

// NewFeistelNetwork создаёт новую сеть Фейстеля
func NewFeistelNetwork(keyExpander core.KeyExpander, roundEncrypter core.RoundEncrypter, rounds int) *FeistelNetwork {
	return &FeistelNetwork{
		keyExpander:    keyExpander,
		roundEncrypter: roundEncrypter,
		rounds:         rounds,
	}
}

// SetEncryptionKey устанавливает ключ шифрования и генерирует раундовые ключи
func (fn *FeistelNetwork) SetEncryptionKey(key []byte) error {
	if fn.keyExpander == nil {
		return errors.New("key expander not set")
	}

	subkeys, err := fn.keyExpander.ExpandKey(key)
	if err != nil {
		return err
	}

	if len(subkeys) != fn.rounds {
		return errors.New("number of subkeys does not match rounds")
	}

	fn.encryptKeys = subkeys

	// Для дешифрования используем ключи в обратном порядке
	fn.decryptKeys = make([][]byte, fn.rounds)
	for i := 0; i < fn.rounds; i++ {
		fn.decryptKeys[i] = fn.encryptKeys[fn.rounds-1-i]
	}

	return nil
}

// SetDecryptionKey устанавливает ключ дешифрования
func (fn *FeistelNetwork) SetDecryptionKey(key []byte) error {
	return fn.SetEncryptionKey(key)
}

// EncryptBlock шифрует блок данных
func (fn *FeistelNetwork) EncryptBlock(block []byte) ([]byte, error) {
	if fn.roundEncrypter == nil {
		return nil, errors.New("round encrypter not set")
	}
	if fn.encryptKeys == nil {
		return nil, errors.New("encryption key not set")
	}

	result := make([]byte, len(block))
	copy(result, block)

	// Выполняем раунды Фейстеля
	for i := 0; i < fn.rounds; i++ {
		var err error
		result, err = fn.roundEncrypter.EncryptRound(result, fn.encryptKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// DecryptBlock дешифрует блок данных
func (fn *FeistelNetwork) DecryptBlock(block []byte) ([]byte, error) {
	if fn.roundEncrypter == nil {
		return nil, errors.New("round encrypter not set")
	}
	if fn.decryptKeys == nil {
		return nil, errors.New("decryption key not set")
	}

	result := make([]byte, len(block))
	copy(result, block)

	// Выполняем раунды Фейстеля с обратными ключами
	for i := 0; i < fn.rounds; i++ {
		var err error
		result, err = fn.roundEncrypter.EncryptRound(result, fn.decryptKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Проверяем, что FeistelNetwork реализует интерфейс SymmetricCipher
var _ core.SymmetricCipher = (*FeistelNetwork)(nil)
