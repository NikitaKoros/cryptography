package feistel

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/common"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/core/feistel"
	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/des"
)

// DESFeistel реализация DES на базе универсальной сети Фейстеля
type DESFeistel struct {
	feistelNetwork *feistel.FeistelNetwork
}

// NewDESFeistel создаёт новый DES на базе сети Фейстеля
func NewDESFeistel() *DESFeistel {
	keySchedule := des.NewDESKeySchedule()
	roundFunc := des.NewDESRoundFunction()
	feistelNetwork := feistel.NewFeistelNetwork(keySchedule, roundFunc, 16)

	return &DESFeistel{
		feistelNetwork: feistelNetwork,
	}
}

// SetEncryptionKey устанавливает ключ шифрования
func (d *DESFeistel) SetEncryptionKey(key []byte) error {
	if len(key) != 8 {
		return errors.New("DES key must be exactly 8 bytes")
	}
	return d.feistelNetwork.SetEncryptionKey(key)
}

// SetDecryptionKey устанавливает ключ дешифрования
func (d *DESFeistel) SetDecryptionKey(key []byte) error {
	return d.SetEncryptionKey(key)
}

// EncryptBlock шифрует один 64-битный блок
func (d *DESFeistel) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("DES block must be exactly 8 bytes")
	}

	// Начальная перестановка IP
	permuted, err := common.Permute(block, des.IP[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	// 16 раундов Фейстеля
	feistelResult, err := d.feistelNetwork.EncryptBlock(permuted)
	if err != nil {
		return nil, err
	}

	// Меняем местами левую и правую части перед финальной перестановкой
	left := feistelResult[:4]
	right := feistelResult[4:]
	swapped := make([]byte, 8)
	copy(swapped[:4], right)
	copy(swapped[4:], left)

	// Финальная перестановка IP^-1
	result, err := common.Permute(swapped, des.IPInverse[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DecryptBlock дешифрует один 64-битный блок
func (d *DESFeistel) DecryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("DES block must be exactly 8 bytes")
	}

	// Начальная перестановка IP
	permuted, err := common.Permute(block, des.IP[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	// 16 раундов Фейстеля с обратными ключами
	feistelResult, err := d.feistelNetwork.DecryptBlock(permuted)
	if err != nil {
		return nil, err
	}

	// Меняем местами левую и правую части перед финальной перестановкой
	left := feistelResult[:4]
	right := feistelResult[4:]
	swapped := make([]byte, 8)
	copy(swapped[:4], right)
	copy(swapped[4:], left)

	// Финальная перестановка IP^-1
	result, err := common.Permute(swapped, des.IPInverse[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (d *DESFeistel) BlockSize() int {
	return 8
}

// Проверяем, что DESFeistel реализует интерфейс SymmetricCipher
var _ core.SymmetricCipher = (*DESFeistel)(nil)
