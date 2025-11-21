package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core/feistel"
)

// DEALCipher реализация алгоритма DEAL
type DEALCipher struct {
	feistelNetwork *feistel.FeistelNetwork
	blockSize      int
}

// NewDEAL128 создаёт DEAL с 128-битным блоком и 128-битным ключом
func NewDEAL128(desCipher core.SymmetricCipher) *DEALCipher {
	return newDEAL(desCipher, 16, 16)
}

// NewDEAL192 создаёт DEAL с 128-битным блоком и 192-битным ключом
func NewDEAL192(desCipher core.SymmetricCipher) *DEALCipher {
	return newDEAL(desCipher, 24, 16)
}

// NewDEAL256 создаёт DEAL с 128-битным блоком и 256-битным ключом
func NewDEAL256(desCipher core.SymmetricCipher) *DEALCipher {
	return newDEAL(desCipher, 32, 16)
}

// NewDEALWithCustomBlockSize создаёт DEAL с пользовательским размером блока
func NewDEALWithCustomBlockSize(desCipher core.SymmetricCipher, keySize, blockSize int) *DEALCipher {
	return newDEAL(desCipher, keySize, blockSize)
}

// newDEAL внутренняя функция создания DEAL
func newDEAL(desCipher core.SymmetricCipher, keySize, blockSize int) *DEALCipher {
	// Создаем адаптер для DES
	desAdapter := NewDESAdapter(desCipher)

	// Создаем экспандер ключей
	keyExpander := NewDEALKeyExpander(keySize, blockSize)

	// Создаем сеть Фейстеля
	feistelNetwork := feistel.NewFeistelNetwork(keyExpander, desAdapter, keyExpander.rounds)

	return &DEALCipher{
		feistelNetwork: feistelNetwork,
		blockSize:      blockSize,
	}
}

// SetEncryptionKey устанавливает ключ шифрования
func (d *DEALCipher) SetEncryptionKey(key []byte) error {
	return d.feistelNetwork.SetEncryptionKey(key)
}

// SetDecryptionKey устанавливает ключ дешифрования
func (d *DEALCipher) SetDecryptionKey(key []byte) error {
	return d.feistelNetwork.SetDecryptionKey(key)
}

// EncryptBlock шифрует один блок данных
func (d *DEALCipher) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != d.blockSize {
		return nil, errors.New("invalid block size for DEAL")
	}

	if d.blockSize != 16 && d.blockSize != 24 && d.blockSize != 32 {
		return nil, errors.New("invalid DEAL block size")
	}

	return d.feistelNetwork.EncryptBlock(block)
}

// DecryptBlock дешифрует один блок данных
func (d *DEALCipher) DecryptBlock(block []byte) ([]byte, error) {
	if len(block) != d.blockSize {
		return nil, errors.New("invalid block size for DEAL")
	}

	if d.blockSize != 16 && d.blockSize != 24 && d.blockSize != 32 {
		return nil, errors.New("invalid DEAL block size")
	}

	return d.feistelNetwork.DecryptBlock(block)
}

// BlockSize возвращает размер блока
func (d *DEALCipher) BlockSize() int {
	return d.blockSize
}

// Проверяем, что DEALCipher реализует интерфейс SymmetricCipher
var _ core.SymmetricCipher = (*DEALCipher)(nil)
