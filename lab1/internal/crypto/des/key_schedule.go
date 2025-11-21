package des

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/common"
)

type DESKeySchedule struct {
	subkeys [][]byte
}

func NewDESKeySchedule() *DESKeySchedule {
	return &DESKeySchedule{
		subkeys: make([][]byte, 16),
	}
}

func (ks *DESKeySchedule) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != 8 {
		return nil, errors.New("DES key must be 8 bytes")
	}
	adjusted := adjustKeyParity(key)

	pc1Bits, err := common.Permute(adjusted, PC1[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}
	pc1Bool := common.BytesToBits(pc1Bits, common.MSBToLSB)[:56]

	c := make([]bool, 28)
	d := make([]bool, 28)
	copy(c, pc1Bool[:28])
	copy(d, pc1Bool[28:56])

	for round := 0; round < 16; round++ {
		shift := ShiftTable[round]
		c = leftShiftBits(c, shift)
		d = leftShiftBits(d, shift)

		cd := make([]bool, 56)
		copy(cd[:28], c)
		copy(cd[28:], d)

		cdBytes := common.BitsToBytes(cd, common.MSBToLSB)
		subkeyBytes, err := common.Permute(cdBytes, PC2[:], common.MSBToLSB, common.OneBased)
		if err != nil {
			return nil, err
		}
		ks.subkeys[round] = subkeyBytes
	}

	return ks.subkeys, nil
}

// adjustKeyParity корректирует биты паритета ключа (каждый байт должен иметь нечётный паритет)
func adjustKeyParity(key []byte) []byte {
	adjusted := make([]byte, 8)
	copy(adjusted, key)
	for i := 0; i < 8; i++ {
		count := 0
		for j := 0; j < 7; j++ {
			if ((adjusted[i] >> uint(j)) & 1) == 1 {
				count++
			}
		}
		if count%2 == 0 {
			adjusted[i] |= 0x01
		} else {
			adjusted[i] &^= 0x01
		}
	}
	return adjusted
}

// leftShiftBits выполняет циклический сдвиг влево для 28-битного блока,
// представленного как []bool длины 28.
func leftShiftBits(bits []bool, shifts int) []bool {
	if len(bits) != 28 {
		panic("leftShiftBits: input must be 28 bits")
	}
	out := make([]bool, 28)
	for i := 0; i < 28; i++ {
		out[i] = bits[(i+shifts)%28]
	}
	return out
}
