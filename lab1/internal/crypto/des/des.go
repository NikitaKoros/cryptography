package des

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/common"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
)

type DES struct {
	keySchedule *DESKeySchedule
	roundFunc   *DESRoundFunction
	encryptKeys [][]byte
	decryptKeys [][]byte
}

func NewDES() *DES {
	return &DES{
		keySchedule: NewDESKeySchedule(),
		roundFunc:   NewDESRoundFunction(),
	}
}

// SetEncryptionKey устанавливает ключ шифрования и формирует раундовые ключи.
func (d *DES) SetEncryptionKey(key []byte) error {
	if len(key) != 8 {
		return errors.New("DES key must be exactly 8 bytes")
	}

	subkeys, err := d.keySchedule.ExpandKey(key)
	if err != nil {
		return err
	}

	d.encryptKeys = subkeys

	// Для дешифрования используем ключи в обратном порядке
	d.decryptKeys = make([][]byte, 16)
	for i := 0; i < 16; i++ {
		d.decryptKeys[i] = d.encryptKeys[15-i]
	}
	return nil
}

// SetDecryptionKey устанавливает ключ дешифрования (тот же, что и для шифрования)
func (d *DES) SetDecryptionKey(key []byte) error {
	return d.SetEncryptionKey(key)
}

// EncryptBlock шифрует один 64-битный блок.
func (d *DES) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("DES block must be exactly 8 bytes")
	}

	permuted, err := common.Permute(block, IP[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 16; i++ {
		permuted, err = d.roundFunc.EncryptRound(permuted, d.encryptKeys[i])
		if err != nil {
			return nil, err
		}
	}

	// Меняем местами левую и правую части перед финальной перестановкой
	left := permuted[:4]
	right := permuted[4:]
	swapped := make([]byte, 8)
	copy(swapped[:4], right)
	copy(swapped[4:], left)

	result, err := common.Permute(swapped, IPInverse[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DecryptBlock дешифрует один 64-битный блок.
func (d *DES) DecryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("DES block must be exactly 8 bytes")
	}

	permuted, err := common.Permute(block, IP[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 16; i++ {
		permuted, err = d.roundFunc.EncryptRound(permuted, d.decryptKeys[i])
		if err != nil {
			return nil, err
		}
	}

	left := permuted[:4]
	right := permuted[4:]
	swapped := make([]byte, 8)
	copy(swapped[:4], right)
	copy(swapped[4:], left)

	result, err := common.Permute(swapped, IPInverse[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (d *DES) BlockSize() int {
	return 8
}

// Проверяем, что DES реализует интерфейс SymmetricCipher
var _ core.SymmetricCipher = (*DES)(nil)
