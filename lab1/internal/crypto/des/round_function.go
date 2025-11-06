package des

import (
	"errors"

	"github.com/NikitaKoros/cryptography/lab1/internal/crypto/common"
)

type DESRoundFunction struct{}

func NewDESRoundFunction() *DESRoundFunction {
	return &DESRoundFunction{}
}

// EncryptRound выполняет один раунд сети Фейстеля.
func (rf *DESRoundFunction) EncryptRound(block []byte, roundKey []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("DES round function: block must be 8 bytes")
	}
	if len(roundKey) != 6 {
		return nil, errors.New("DES round function: round key must be 6 bytes (48 bits)")
	}

	// Разделяем блок на левую и правую части
	left := block[:4]
	right := block[4:]

	// Сохраняем оригинальную правую часть
	originalRight := make([]byte, 4)
	copy(originalRight, right)

	// Вычисляем f(R, K)
	fResult, err := fFunction(right, roundKey)
	if err != nil {
		return nil, err
	}

	// Выполняем XOR левой части с результатом f-функции
	newRight, err := xorBytes(left, fResult)
	if err != nil {
		return nil, err
	}

	// Новая левая часть = оригинальная правая часть
	newLeft := originalRight

	// Объединяем результаты
	result := make([]byte, 8)
	copy(result[:4], newLeft)
	copy(result[4:], newRight)

	return result, nil
}

// fFunction реализует f(R, K) функцию DES.
func fFunction(right []byte, roundKey []byte) ([]byte, error) {
	if len(right) != 4 {
		return nil, errors.New("fFunction: right half must be 4 bytes (32 bits)")
	}
	if len(roundKey) != 6 {
		return nil, errors.New("fFunction: round key must be 6 bytes (48 bits)")
	}

	// Расширяем R с 32 до 48 бит
	expanded, err := common.Permute(right, Expansion[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	// XOR с раундовым ключом
	xored, err := xorBytes(expanded, roundKey)
	if err != nil {
		return nil, err
	}

	// Применяем S-блоки
	sboxResult, err := applySBoxes(xored)
	if err != nil {
		return nil, err
	}

	// Применяем перестановку P
	result, err := common.Permute(sboxResult, P[:], common.MSBToLSB, common.OneBased)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// applySBoxes применяет S-блоки к 48-битному блоку.
func applySBoxes(data []byte) ([]byte, error) {
	if len(data) != 6 {
		return nil, errors.New("applySBoxes: input must be 6 bytes (48 bits)")
	}

	result := make([]byte, 4)

	for i := 0; i < 8; i++ {
		// Извлекаем 6 бит для текущего S-блока
		bits := make([]bool, 6)
		for j := 0; j < 6; j++ {
			bytePos := (i*6 + j) / 8
			bitPos := uint(7 - ((i*6 + j) % 8))
			if bytePos >= len(data) {
				return nil, errors.New("applySBoxes: bit extraction out of range")
			}
			bits[j] = (data[bytePos]>>bitPos)&1 == 1
		}

		// Вычисляем строку и столбец
		row := (boolToInt(bits[0]) << 1) | boolToInt(bits[5])
		col := (boolToInt(bits[1]) << 3) | (boolToInt(bits[2]) << 2) |
			(boolToInt(bits[3]) << 1) | boolToInt(bits[4])

		// Получаем значение из S-блока
		sboxValue := SBoxes[i][row][col]

		// Записываем 4 бита в результат
		for j := 0; j < 4; j++ {
			bytePos := (i*4 + j) / 8
			bitPos := uint(7 - ((i*4 + j) % 8))
			if (sboxValue>>uint(3-j))&1 == 1 {
				result[bytePos] |= 1 << bitPos
			}
		}
	}

	return result, nil
}

// xorBytes выполняет побитовый XOR двух байтовых массивов.
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("xorBytes: arrays must have same length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
