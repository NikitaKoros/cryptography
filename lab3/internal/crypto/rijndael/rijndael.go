package rijndael

import (
	"errors"
	"fmt"

	"github.com/NikitaKoros/cryptography/lab3/internal/gf256"
)

// Rijndael представляет алгоритм шифрования Rijndael
type Rijndael struct {
	blockSize    int      // Размер блока в байтах (16, 24, 32)
	keySize      int      // Размер ключа в байтах (16, 24, 32)
	Nb           int      // Количество 32-битных слов в блоке
	Nk           int      // Количество 32-битных слов в ключе
	Nr           int      // Количество раундов
	gf           *gf256.GF256
	sbox         *SBox
	roundKeys    [][]byte // Раундовые ключи для шифрования
	decRoundKeys [][]byte // Раундовые ключи для дешифрования
}

// NewRijndael создает новый экземпляр Rijndael с заданными параметрами
// blockSize и keySize должны быть 16, 24 или 32 байта (128, 192 или 256 бит)
// modulus - неприводимый полином для GF(2^8)
func NewRijndael(blockSize, keySize int, modulus byte) (*Rijndael, error) {
	if blockSize != 16 && blockSize != 24 && blockSize != 32 {
		return nil, errors.New("недопустимый размер блока: должен быть 16, 24 или 32 байта")
	}
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("недопустимый размер ключа: должен быть 16, 24 или 32 байта")
	}

	gf, err := gf256.NewGF256(modulus)
	if err != nil {
		return nil, err
	}

	sbox, err := NewSBox(modulus)
	if err != nil {
		return nil, err
	}

	Nb := blockSize / 4
	Nk := keySize / 4

	// Вычисляем количество раундов согласно спецификации Rijndael
	Nr := calculateRounds(Nb, Nk)

	return &Rijndael{
		blockSize: blockSize,
		keySize:   keySize,
		Nb:        Nb,
		Nk:        Nk,
		Nr:        Nr,
		gf:        gf,
		sbox:      sbox,
	}, nil
}

// calculateRounds вычисляет количество раундов для заданных Nb и Nk
func calculateRounds(Nb, Nk int) int {
	// Максимум из (Nb, Nk) + 6
	max := Nb
	if Nk > max {
		max = Nk
	}
	return max + 6
}

// SetEncryptionKey устанавливает ключ шифрования и выполняет расширение ключа
func (r *Rijndael) SetEncryptionKey(key []byte) error {
	if len(key) != r.keySize {
		return fmt.Errorf("неверный размер ключа: ожидается %d байт, получено %d", r.keySize, len(key))
	}

	var err error
	r.roundKeys, err = r.expandKey(key)
	return err
}

// SetDecryptionKey устанавливает ключ дешифрования
func (r *Rijndael) SetDecryptionKey(key []byte) error {
	// Сначала генерируем ключи шифрования
	if err := r.SetEncryptionKey(key); err != nil {
		return err
	}

	// Для дешифрования используем те же ключи в обратном порядке
	// Применение InvMixColumns к ключам не требуется в стандартном алгоритме
	r.decRoundKeys = make([][]byte, len(r.roundKeys))

	// Копируем ключи в обратном порядке
	for i := 0; i <= r.Nr; i++ {
		r.decRoundKeys[i] = make([]byte, r.blockSize)
		copy(r.decRoundKeys[i], r.roundKeys[r.Nr-i])
	}

	return nil
}

// BlockSize возвращает размер блока в байтах
func (r *Rijndael) BlockSize() int {
	return r.blockSize
}

// EncryptBlock шифрует один блок данных
func (r *Rijndael) EncryptBlock(plaintext []byte) ([]byte, error) {
	if len(plaintext) != r.blockSize {
		return nil, fmt.Errorf("неверный размер блока: ожидается %d байт, получено %d", r.blockSize, len(plaintext))
	}
	if r.roundKeys == nil {
		return nil, errors.New("ключ шифрования не установлен")
	}

	state := make([]byte, r.blockSize)
	copy(state, plaintext)

	// Начальное добавление раундового ключа
	r.addRoundKey(state, r.roundKeys[0])

	// Основные раунды
	for round := 1; round < r.Nr; round++ {
		r.sbox.SubBytes(state)
		r.shiftRows(state)
		r.mixColumns(state)
		r.addRoundKey(state, r.roundKeys[round])
	}

	// Финальный раунд (без MixColumns)
	r.sbox.SubBytes(state)
	r.shiftRows(state)
	r.addRoundKey(state, r.roundKeys[r.Nr])

	return state, nil
}

// DecryptBlock дешифрует один блок данных
func (r *Rijndael) DecryptBlock(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != r.blockSize {
		return nil, fmt.Errorf("неверный размер блока: ожидается %d байт, получено %d", r.blockSize, len(ciphertext))
	}
	if r.decRoundKeys == nil {
		return nil, errors.New("ключ дешифрования не установлен")
	}

	state := make([]byte, r.blockSize)
	copy(state, ciphertext)

	// Начальное добавление раундового ключа
	r.addRoundKey(state, r.decRoundKeys[0])

	// Основные раунды в обратном порядке
	for round := 1; round < r.Nr; round++ {
		r.invShiftRows(state)
		r.sbox.InvSubBytes(state)
		r.addRoundKey(state, r.decRoundKeys[round])
		r.invMixColumns(state)
	}

	// Финальный раунд (без InvMixColumns)
	r.invShiftRows(state)
	r.sbox.InvSubBytes(state)
	r.addRoundKey(state, r.decRoundKeys[r.Nr])

	return state, nil
}

// addRoundKey выполняет XOR состояния с раундовым ключом
func (r *Rijndael) addRoundKey(state, roundKey []byte) {
	for i := 0; i < r.blockSize; i++ {
		state[i] ^= roundKey[i]
	}
}

// shiftRows выполняет циклический сдвиг строк влево
func (r *Rijndael) shiftRows(state []byte) {
	temp := make([]byte, r.blockSize)
	copy(temp, state)

	for row := 0; row < 4; row++ {
		for col := 0; col < r.Nb; col++ {
			// Новая позиция: сдвиг на row позиций влево
			newCol := (col + row) % r.Nb
			state[row+4*col] = temp[row+4*newCol]
		}
	}
}

// invShiftRows выполняет обратный циклический сдвиг строк
func (r *Rijndael) invShiftRows(state []byte) {
	temp := make([]byte, r.blockSize)
	copy(temp, state)

	for row := 0; row < 4; row++ {
		for col := 0; col < r.Nb; col++ {
			// Обратный сдвиг: вправо на row позиций
			newCol := (col - row + r.Nb) % r.Nb
			state[row+4*col] = temp[row+4*newCol]
		}
	}
}

// mixColumns выполняет перемешивание столбцов
func (r *Rijndael) mixColumns(state []byte) {
	temp := make([]byte, 4)

	for col := 0; col < r.Nb; col++ {
		offset := col * 4

		// Сохраняем исходный столбец
		for i := 0; i < 4; i++ {
			temp[i] = state[offset+i]
		}

		// Умножение матрицы на столбец в GF(2^8)
		// Матрица MixColumns:
		// 02 03 01 01
		// 01 02 03 01
		// 01 01 02 03
		// 03 01 01 02

		state[offset+0] = gf256.Add(
			gf256.Add(r.gf.Multiply(0x02, temp[0]), r.gf.Multiply(0x03, temp[1])),
			gf256.Add(temp[2], temp[3]),
		)

		state[offset+1] = gf256.Add(
			gf256.Add(temp[0], r.gf.Multiply(0x02, temp[1])),
			gf256.Add(r.gf.Multiply(0x03, temp[2]), temp[3]),
		)

		state[offset+2] = gf256.Add(
			gf256.Add(temp[0], temp[1]),
			gf256.Add(r.gf.Multiply(0x02, temp[2]), r.gf.Multiply(0x03, temp[3])),
		)

		state[offset+3] = gf256.Add(
			gf256.Add(r.gf.Multiply(0x03, temp[0]), temp[1]),
			gf256.Add(temp[2], r.gf.Multiply(0x02, temp[3])),
		)
	}
}

// invMixColumns выполняет обратное перемешивание столбцов
func (r *Rijndael) invMixColumns(state []byte) {
	temp := make([]byte, 4)

	for col := 0; col < r.Nb; col++ {
		offset := col * 4

		for i := 0; i < 4; i++ {
			temp[i] = state[offset+i]
		}

		// Обратная матрица MixColumns:
		// 0e 0b 0d 09
		// 09 0e 0b 0d
		// 0d 09 0e 0b
		// 0b 0d 09 0e

		state[offset+0] = gf256.Add(
			gf256.Add(r.gf.Multiply(0x0e, temp[0]), r.gf.Multiply(0x0b, temp[1])),
			gf256.Add(r.gf.Multiply(0x0d, temp[2]), r.gf.Multiply(0x09, temp[3])),
		)

		state[offset+1] = gf256.Add(
			gf256.Add(r.gf.Multiply(0x09, temp[0]), r.gf.Multiply(0x0e, temp[1])),
			gf256.Add(r.gf.Multiply(0x0b, temp[2]), r.gf.Multiply(0x0d, temp[3])),
		)

		state[offset+2] = gf256.Add(
			gf256.Add(r.gf.Multiply(0x0d, temp[0]), r.gf.Multiply(0x09, temp[1])),
			gf256.Add(r.gf.Multiply(0x0e, temp[2]), r.gf.Multiply(0x0b, temp[3])),
		)

		state[offset+3] = gf256.Add(
			gf256.Add(r.gf.Multiply(0x0b, temp[0]), r.gf.Multiply(0x0d, temp[1])),
			gf256.Add(r.gf.Multiply(0x09, temp[2]), r.gf.Multiply(0x0e, temp[3])),
		)
	}
}
