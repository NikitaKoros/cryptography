package rijndael

import (
	"github.com/NikitaKoros/cryptography/lab3/internal/gf256"
)

// SBox представляет прямую и обратную таблицы подстановки
type SBox struct {
	forward [256]byte
	inverse [256]byte
}

// NewSBox создает новые таблицы подстановки для заданного модуля GF(2^8)
func NewSBox(modulus byte) (*SBox, error) {
	gf, err := gf256.NewGF256(modulus)
	if err != nil {
		return nil, err
	}

	sbox := &SBox{}

	// Генерируем прямую S-box
	for i := 0; i < 256; i++ {
		// Шаг 1: Берем обратный элемент в GF(2^8)
		var inv byte
		if i == 0 {
			inv = 0 // Обратный для 0 - это 0 по соглашению
		} else {
			inv, err = gf.Inverse(byte(i))
			if err != nil {
				inv = 0 // Если не удалось найти обратный, используем 0
			}
		}

		// Шаг 2: Применяем аффинное преобразование
		// S(x) = Ax + b, где A - матрица, b - вектор
		// Стандартное аффинное преобразование AES:
		// bi = xi ⊕ x(i+4) mod 8 ⊕ x(i+5) mod 8 ⊕ x(i+6) mod 8 ⊕ x(i+7) mod 8 ⊕ ci
		// где c = 0x63 = 01100011

		result := byte(0)
		c := byte(0x63) // Константа из стандарта AES

		for bit := 0; bit < 8; bit++ {
			// Вычисляем бит результата
			bitVal := getBit(inv, bit) ^
				getBit(inv, (bit+4)%8) ^
				getBit(inv, (bit+5)%8) ^
				getBit(inv, (bit+6)%8) ^
				getBit(inv, (bit+7)%8) ^
				getBit(c, bit)

			if bitVal != 0 {
				result |= (1 << bit)
			}
		}

		sbox.forward[i] = result
	}

	// Генерируем обратную S-box независимо (не через прямую)
	// Обратная операция: сначала обратное аффинное преобразование, потом обратный элемент
	for i := 0; i < 256; i++ {
		// Шаг 1: Применяем обратное аффинное преобразование
		// Обратная матрица для AES: bi = x(i+2) mod 8 ⊕ x(i+5) mod 8 ⊕ x(i+7) mod 8
		// Константа для обратного преобразования: d = 0x05

		// Сначала применяем обратную матрицу
		temp := byte(0)
		for bit := 0; bit < 8; bit++ {
			bitVal := getBit(byte(i), (bit+2)%8) ^
				getBit(byte(i), (bit+5)%8) ^
				getBit(byte(i), (bit+7)%8)

			if bitVal != 0 {
				temp |= (1 << bit)
			}
		}

		// Затем XOR с константой обратного преобразования
		// Для стандартного AES: если прямая константа c = 0x63,
		// то обратная константа d = A^(-1) * c = 0x05
		result := temp ^ 0x05

		// Шаг 2: Берем обратный элемент в GF(2^8)
		var invElem byte
		if result == 0 {
			invElem = 0
		} else {
			invElem, err = gf.Inverse(result)
			if err != nil {
				invElem = 0
			}
		}

		sbox.inverse[i] = invElem
	}

	return sbox, nil
}

// getBit возвращает значение бита на позиции pos (0-7)
func getBit(b byte, pos int) byte {
	return (b >> pos) & 1
}

// SubBytes применяет прямую S-box подстановку
func (s *SBox) SubBytes(state []byte) {
	for i := range state {
		state[i] = s.forward[state[i]]
	}
}

// InvSubBytes применяет обратную S-box подстановку
func (s *SBox) InvSubBytes(state []byte) {
	for i := range state {
		state[i] = s.inverse[state[i]]
	}
}

// GetForward возвращает прямую S-box
func (s *SBox) GetForward() [256]byte {
	return s.forward
}

// GetInverse возвращает обратную S-box
func (s *SBox) GetInverse() [256]byte {
	return s.inverse
}
