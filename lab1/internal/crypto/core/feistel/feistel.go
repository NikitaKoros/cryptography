package feistel

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

// FeistelNetwork универсальная реализация сети Фейстеля
type FeistelNetwork struct {
	KeyExpander    core.KeyExpander
	RoundEncrypter core.RoundEncrypter
	Rounds         int
	EncryptKeys    [][]byte
	DecryptKeys    [][]byte
}

// NewFeistelNetwork создаёт новую сеть Фейстеля
func NewFeistelNetwork(KeyExpander core.KeyExpander, RoundEncrypter core.RoundEncrypter, Rounds int) *FeistelNetwork {
	return &FeistelNetwork{
		KeyExpander:    KeyExpander,
		RoundEncrypter: RoundEncrypter,
		Rounds:         Rounds,
	}
}

// SetEncryptionKey устанавливает ключ шифрования и генерирует раундовые ключи
func (fn *FeistelNetwork) SetEncryptionKey(key []byte) error {
	if fn.KeyExpander == nil {
		return errors.New("key expander not set")
	}

	subkeys, err := fn.KeyExpander.ExpandKey(key)
	if err != nil {
		return err
	}

	if len(subkeys) != fn.Rounds {
		return errors.New("number of subkeys does not match Rounds")
	}

	fn.EncryptKeys = subkeys

	// Для дешифрования используем ключи в обратном порядке
	fn.DecryptKeys = make([][]byte, fn.Rounds)
	for i := 0; i < fn.Rounds; i++ {
		fn.DecryptKeys[i] = fn.EncryptKeys[fn.Rounds-1-i]
	}

	return nil
}

// SetDecryptionKey устанавливает ключ дешифрования
func (fn *FeistelNetwork) SetDecryptionKey(key []byte) error {
	return fn.SetEncryptionKey(key)
}

// EncryptBlock шифрует блок данных
func (fn *FeistelNetwork) EncryptBlock(block []byte) ([]byte, error) {
	if fn.RoundEncrypter == nil {
		return nil, errors.New("round encrypter not set")
	}
	if fn.EncryptKeys == nil {
		return nil, errors.New("encryption key not set")
	}

	result := make([]byte, len(block))
	copy(result, block)

	// Выполняем раунды Фейстеля
	for i := 0; i < fn.Rounds; i++ {
		var err error
		result, err = fn.RoundEncrypter.EncryptRound(result, fn.EncryptKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// DecryptBlock дешифрует блок данных
func (fn *FeistelNetwork) DecryptBlock(block []byte) ([]byte, error) {
	if fn.RoundEncrypter == nil {
		return nil, errors.New("round encrypter not set")
	}
	if fn.DecryptKeys == nil {
		return nil, errors.New("decryption key not set")
	}

	result := make([]byte, len(block))
	copy(result, block)

	// Выполняем раунды Фейстеля с обратными ключами
	for i := 0; i < fn.Rounds; i++ {
		var err error
		result, err = fn.RoundEncrypter.EncryptRound(result, fn.DecryptKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (d *FeistelNetwork) BlockSize() int {
	return 8
}

// Проверяем, что FeistelNetwork реализует интерфейс SymmetricCipher
var _ core.SymmetricCipher = (*FeistelNetwork)(nil)
