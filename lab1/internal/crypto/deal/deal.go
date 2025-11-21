package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core/feistel"
)

type DEALCipher struct {
	feistelNetwork *feistel.FeistelNetwork
	blockSize      int
}

func NewDEAL128(desCipher core.SymmetricCipher) *DEALCipher {
	return newDEAL(desCipher, 16)
}

func NewDEAL192(desCipher core.SymmetricCipher) *DEALCipher {
	return newDEAL(desCipher, 24)
}

func NewDEAL256(desCipher core.SymmetricCipher) *DEALCipher {
	return newDEAL(desCipher, 32)
}

func newDEAL(desCipher core.SymmetricCipher, keySize int) *DEALCipher {
	blockSize := 16

	desAdapter := NewDESAdapter(desCipher)

	keyExpander := NewDEALKeyExpander(keySize)

	feistelNetwork := feistel.NewFeistelNetwork(keyExpander, desAdapter, keyExpander.rounds)

	return &DEALCipher{
		feistelNetwork: feistelNetwork,
		blockSize:      blockSize,
	}
}

func (d *DEALCipher) SetEncryptionKey(key []byte) error {
	return d.feistelNetwork.SetEncryptionKey(key)
}

func (d *DEALCipher) SetDecryptionKey(key []byte) error {
	return d.feistelNetwork.SetDecryptionKey(key)
}

func (d *DEALCipher) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != d.blockSize {
		return nil, errors.New("invalid block size for DEAL")
	}

	return d.feistelNetwork.EncryptBlock(block)
}

func (d *DEALCipher) DecryptBlock(block []byte) ([]byte, error) {
	if len(block) != d.blockSize {
		return nil, errors.New("invalid block size for DEAL")
	}

	return d.feistelNetwork.DecryptBlock(block)
}

func (d *DEALCipher) BlockSize() int {
	return d.blockSize
}

var _ core.SymmetricCipher = (*DEALCipher)(nil)
