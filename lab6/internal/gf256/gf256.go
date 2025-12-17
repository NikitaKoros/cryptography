package gf256

import (
	"errors"
	"fmt"
)

// GF256 представляет конечное поле GF(2^8)
type GF256 struct {
	modulus byte // неприводимый полином-модуль
}

// NewGF256 создает новый экземпляр GF(2^8) с заданным модулем
func NewGF256(modulus byte) (*GF256, error) {
	if !IsIrreducible(modulus) {
		return nil, errors.New("модуль должен быть неприводимым полиномом над GF(2^8)")
	}
	return &GF256{modulus: modulus}, nil
}

// Add выполняет сложение двух элементов в GF(2^8)
// Сложение - это побитовый XOR
func Add(a, b byte) byte {
	return a ^ b
}

// Multiply выполняет умножение двух элементов в GF(2^8) по заданному модулю
func (gf *GF256) Multiply(a, b byte) byte {
	var result byte = 0
	var temp byte = a

	for i := 0; i < 8; i++ {
		// Если i-й бит b равен 1, добавляем temp к результату
		if (b & 1) == 1 {
			result ^= temp
		}

		// Проверяем старший бит temp
		highBitSet := (temp & 0x80) != 0

		// Умножаем temp на x (сдвиг влево)
		temp <<= 1

		// Если старший бит был установлен, выполняем редукцию по модулю
		if highBitSet {
			temp ^= gf.modulus
		}

		// Переходим к следующему биту b
		b >>= 1
	}

	return result
}

// Inverse вычисляет обратный элемент в GF(2^8) по заданному модулю
// Использует расширенный алгоритм Евклида
func (gf *GF256) Inverse(a byte) (byte, error) {
	if a == 0 {
		return 0, errors.New("обратный элемент для 0 не существует")
	}

	// Расширенный алгоритм Евклида для полиномов над GF(2)
	// Модуль представлен как 9-битное число (x^8 + младшие биты)
	u, v := uint16(a), uint16(gf.modulus)|0x100
	g1, g2 := uint16(1), uint16(0)

	for u != 0 {
		// Вычисляем степени
		degU := degree(u)
		degV := degree(v)

		if degU < degV {
			// Меняем местами u и v, g1 и g2
			u, v = v, u
			g1, g2 = g2, g1
			degU, degV = degV, degU
		}

		// u = u + v * x^(degU - degV)
		shift := degU - degV
		u ^= v << shift
		g1 ^= g2 << shift
	}

	if v != 1 {
		return 0, errors.New("обратный элемент не существует (элементы не взаимно просты)")
	}

	return byte(g2 & 0xFF), nil
}

// degree вычисляет степень полинома (позицию старшего бита)
func degree(poly uint16) int {
	if poly == 0 {
		return -1
	}
	deg := 0
	for poly > 1 {
		poly >>= 1
		deg++
	}
	return deg
}

// IsIrreducible проверяет, является ли полином неприводимым над GF(2^8)
// poly представляет младшие 8 бит полинома степени 8, старший бит (x^8) подразумевается
func IsIrreducible(poly byte) bool {
	// Для полинома степени 8 проверяем делимость на все полиномы меньшей степени
	// Используем 9-битное представление (добавляем старший бит x^8)
	poly9 := uint16(poly) | 0x100 // x^8 + остальные члены

	// Пробуем делить на все полиномы степени от 1 до 7
	for divisor := uint16(2); divisor < 0x100; divisor++ {
		if isDivisible9bit(poly9, divisor) {
			return false
		}
	}

	return true
}

// isDivisible9bit проверяет делимость для 9-битных полиномов
func isDivisible9bit(poly, divisor uint16) bool {
	if divisor == 0 {
		return false
	}

	remainder := poly

	for {
		degRem := degree(remainder)
		degDiv := degree(divisor)

		if degRem < degDiv {
			break
		}

		shift := degRem - degDiv
		remainder ^= divisor << shift
	}

	return remainder == 0
}

// isDivisible проверяет, делится ли poly на divisor без остатка
func isDivisible(poly, divisor byte) bool {
	if divisor == 0 {
		return false
	}

	remainder := uint16(poly)
	div := uint16(divisor)

	for {
		degRem := degree(remainder)
		degDiv := degree(div)

		if degRem < degDiv {
			break
		}

		shift := degRem - degDiv
		remainder ^= div << shift
	}

	return remainder == 0
}

// GetAllIrreduciblePolynomials возвращает все неприводимые полиномы степени 8
func GetAllIrreduciblePolynomials() []byte {
	var result []byte

	// Проверяем все возможные комбинации младших 8 бит
	// Старший бит (x^8) подразумевается всегда установленным
	for i := 0; i < 256; i++ {
		poly := byte(i)
		if IsIrreducible(poly) {
			result = append(result, poly)
		}
	}

	return result
}

// FactorPolynomial раскладывает полином на неприводимые множители
func FactorPolynomial(poly uint64) []uint64 {
	if poly <= 1 {
		return []uint64{}
	}

	factors := make([]uint64, 0)

	// Пробуем делить на простые полиномы
	for divisor := uint64(2); divisor*divisor <= poly; {
		if polyDivides(poly, divisor) {
			factors = append(factors, divisor)
			poly = polyDivide(poly, divisor)
		} else {
			divisor = nextPoly(divisor)
		}
	}

	if poly > 1 {
		factors = append(factors, poly)
	}

	return factors
}

// polyDivides проверяет, делится ли poly на divisor
func polyDivides(poly, divisor uint64) bool {
	if divisor == 0 {
		return false
	}

	remainder := poly

	for {
		degRem := degree64(remainder)
		degDiv := degree64(divisor)

		if degRem < degDiv {
			break
		}

		shift := degRem - degDiv
		remainder ^= divisor << shift
	}

	return remainder == 0
}

// polyDivide делит poly на divisor
func polyDivide(poly, divisor uint64) uint64 {
	if divisor == 0 {
		return poly
	}

	quotient := uint64(0)
	remainder := poly

	for {
		degRem := degree64(remainder)
		degDiv := degree64(divisor)

		if degRem < degDiv {
			break
		}

		shift := degRem - degDiv
		quotient ^= uint64(1) << shift
		remainder ^= divisor << shift
	}

	return quotient
}

// degree64 вычисляет степень полинома (для uint64)
func degree64(poly uint64) int {
	if poly == 0 {
		return -1
	}
	deg := 0
	for poly > 1 {
		poly >>= 1
		deg++
	}
	return deg
}

// nextPoly возвращает следующий полином для проверки делимости
func nextPoly(current uint64) uint64 {
	return current + 1
}

// XTime выполняет умножение на x в GF(2^8) (специальная оптимизация для Rijndael)
func (gf *GF256) XTime(a byte) byte {
	highBitSet := (a & 0x80) != 0
	result := a << 1

	if highBitSet {
		result ^= gf.modulus
	}

	return result
}

// String возвращает строковое представление элемента GF(2^8)
func ElementToString(a byte) string {
	return fmt.Sprintf("0x%02X", a)
}

// PolyToString возвращает строковое представление полинома степени 8
// poly - младшие 8 бит, старший бит x^8 подразумевается
func PolyToString(poly byte) string {
	terms := make([]string, 0)

	// Добавляем x^8 (всегда присутствует для полиномов степени 8)
	terms = append(terms, "x^8")

	// Проверяем младшие 8 бит
	for i := 7; i >= 0; i-- {
		if (poly & (1 << i)) != 0 {
			if i == 0 {
				terms = append(terms, "1")
			} else if i == 1 {
				terms = append(terms, "x")
			} else {
				terms = append(terms, fmt.Sprintf("x^%d", i))
			}
		}
	}

	result := ""
	for i, term := range terms {
		if i > 0 {
			result += " + "
		}
		result += term
	}

	return result
}
