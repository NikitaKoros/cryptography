package common

import (
	"errors"
)

// BitOrder определяет порядок индексирования битов
type BitOrder int

const (
	LSBToMSB BitOrder = iota // от младшего к старшему (бит 0 — LSB)
	MSBToLSB                 // от старшего к младшему (бит 7 — MSB)
)

// StartIndex определяет начальный индекс
type StartIndex int

const (
	ZeroBased StartIndex = iota // начинается с 0
	OneBased                    // начинается с 1
)

// Permute выполняет перестановку битов в соответствии с правилом.
// rule — массив индексов (позиции битов в исходном блоке), например PC-1, PC-2 и т.п.
// Возвращаемая длина результата = ceil(len(rule)/8)
func Permute(data []byte, rule []int, bitOrder BitOrder, startIndex StartIndex) ([]byte, error) {
	if len(rule) == 0 {
		return nil, errors.New("Permute: empty rule")
	}

	inputBits := BytesToBits(data, bitOrder)

	// Приведём rule к zero-based индексам в битовом представлении
	outputBits := make([]bool, len(rule))
	for i, pos := range rule {
		adjusted := pos
		if startIndex == OneBased {
			adjusted = pos - 1
		}
		// теперь adjusted — индекс бита в терминах FIPS (левый=0) или в общем — см. BytesToBits/ordering
		if adjusted < 0 || adjusted >= len(inputBits) {
			// безопаснее — вернуть ошибку
			return nil, errors.New("Permute: rule index out of range")
		}
		outputBits[i] = inputBits[adjusted]
	}

	return BitsToBytes(outputBits, bitOrder), nil
}

// BytesToBits конвертирует слайс байт в слайс битов ([]bool).
// Порядок битов внутри байта зависит от bitOrder:
// - MSBToLSB: первый (индекс 0) бит в возвращаемом массиве — старший бит первого байта (бит 7).
// - LSBToMSB: первый бит — младший бит первого байта (бит 0).
// Таким образом нумерация битов соответствует позициям, которые используются в правилах перестановок.
func BytesToBits(data []byte, bitOrder BitOrder) []bool {
	bits := make([]bool, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			if bitOrder == LSBToMSB {
				// младший бит первым
				bits[i*8+j] = ((b >> uint(j)) & 1) == 1
			} else {
				// MSBToLSB — старший бит первым: j=0 -> бит 7
				bits[i*8+j] = ((b >> uint(7-j)) & 1) == 1
			}
		}
	}
	return bits
}

// BitsToBytes преобразует []bool (битовый массив) обратно в []byte.
// Возвращаемая длина байтов — минимальная, покрывающая все биты.
func BitsToBytes(bits []bool, bitOrder BitOrder) []byte {
	nBytes := (len(bits) + 7) / 8
	result := make([]byte, nBytes)
	for i := 0; i < len(bits); i++ {
		bytePos := i / 8
		if bitOrder == LSBToMSB {
			bitPos := uint(i % 8)
			if bits[i] {
				result[bytePos] |= 1 << bitPos
			}
		} else {
			// MSBToLSB: внутри байта битовый индекс 0 -> бит7
			bitPos := uint(7 - (i % 8))
			if bits[i] {
				result[bytePos] |= 1 << bitPos
			}
		}
	}
	return result
}
