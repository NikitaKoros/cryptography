package deal

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

type DESAdapter struct {
	des core.SymmetricCipher
}

func NewDESAdapter(des core.SymmetricCipher) *DESAdapter {
	return &DESAdapter{
		des: des,
	}
}

func (da *DESAdapter) EncryptRound(block []byte, roundKey []byte) ([]byte, error) {
	blockSize := len(block)
	if blockSize != 16 {
		return nil, errors.New("DEAL block size must be 16 bytes (128 bits)")
	}

	halfSize := blockSize / 2

	left := block[:halfSize]
	right := block[halfSize:]

	if err := da.des.SetEncryptionKey(roundKey); err != nil {
		return nil, err
	}

	fResult, err := da.des.EncryptBlock(right)
	if err != nil {
		return nil, err
	}

	newLeft := xorBytes(left, fResult)

	result := make([]byte, blockSize)
	copy(result[:halfSize], newLeft)
	copy(result[halfSize:], right)

	return result, nil
}

func (da *DESAdapter) DecryptRound(block []byte, roundKey []byte) ([]byte, error) {
	return da.EncryptRound(block, roundKey)
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xorBytes: slices must have equal length")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

var _ core.RoundEncrypter = (*DESAdapter)(nil)
