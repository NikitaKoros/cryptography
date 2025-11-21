package deal

import (
	"crypto/sha256"
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

type DEALKeyExpander struct {
	keySize int
	rounds  int
}

func NewDEALKeyExpander(keySize int) *DEALKeyExpander {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return &DEALKeyExpander{
			keySize: keySize,
			rounds:  0,
		}
	}

	rounds := 6
	if keySize == 32 { // DEAL-256
		rounds = 8
	}

	return &DEALKeyExpander{
		keySize: keySize,
		rounds:  rounds,
	}
}

func (ke *DEALKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != ke.keySize {
		return nil, errors.New("invalid key size for DEAL")
	}

	if ke.keySize != 16 && ke.keySize != 24 && ke.keySize != 32 {
		return nil, errors.New("unsupported key size for DEAL")
	}

	subkeys := make([][]byte, ke.rounds)

	for i := 0; i < ke.rounds; i++ {
		roundData := make([]byte, len(key)+1)
		copy(roundData, key)
		roundData[len(key)] = byte(i + 1)

		hash := sha256.Sum256(roundData)

		subkey := make([]byte, 8)
		copy(subkey, hash[:8])

		subkeys[i] = subkey
	}

	return subkeys, nil
}

func (ke *DEALKeyExpander) ExpandDecryptionKeys(key []byte) ([][]byte, error) {
	encryptionKeys, err := ke.ExpandKey(key)
	if err != nil {
		return nil, err
	}

	decryptionKeys := make([][]byte, len(encryptionKeys))
	for i := 0; i < len(encryptionKeys); i++ {
		decryptionKeys[i] = encryptionKeys[len(encryptionKeys)-1-i]
	}

	return decryptionKeys, nil
}

func (ke *DEALKeyExpander) Rounds() int {
	return ke.rounds
}

var _ core.KeyExpander = (*DEALKeyExpander)(nil)
