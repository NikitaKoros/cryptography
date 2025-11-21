package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

type DEALFactory struct{}

func NewDEALFactory() *DEALFactory {
	return &DEALFactory{}
}

func (df *DEALFactory) CreateDEAL(keySize int) (core.SymmetricCipher, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("DEAL supports only 128, 192, or 256-bit keys")
	}

	desCipher := des.NewDES()

	switch keySize {
	case 16:
		return NewDEAL128(desCipher), nil
	case 24:
		return NewDEAL192(desCipher), nil
	case 32:
		return NewDEAL256(desCipher), nil
	default:
		return nil, errors.New("unsupported key size")
	}
}

func (df *DEALFactory) CreateDEALWithCustomDES(desCipher core.SymmetricCipher, keySize int) (core.SymmetricCipher, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("DEAL supports only 128, 192, or 256-bit keys")
	}

	switch keySize {
	case 16:
		return NewDEAL128(desCipher), nil
	case 24:
		return NewDEAL192(desCipher), nil
	case 32:
		return NewDEAL256(desCipher), nil
	default:
		return nil, errors.New("unsupported key size")
	}
}
