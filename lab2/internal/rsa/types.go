package rsa

import "math/big"

// TestType представляет тип теста простоты (nested enum)
type TestType int

const (
	// TestTypeFermat - тест Ферма
	TestTypeFermat TestType = iota
	// TestTypeSolovayStrassen - тест Соловея-Штрассена
	TestTypeSolovayStrassen
	// TestTypeMillerRabin - тест Миллера-Рабина
	TestTypeMillerRabin
)

// String возвращает строковое представление типа теста
func (t TestType) String() string {
	switch t {
	case TestTypeFermat:
		return "Fermat"
	case TestTypeSolovayStrassen:
		return "Solovay-Strassen"
	case TestTypeMillerRabin:
		return "Miller-Rabin"
	default:
		return "Unknown"
	}
}

// PublicKey представляет открытый ключ RSA
type PublicKey struct {
	N *big.Int // Модуль RSA (n = p * q)
	E *big.Int // Открытая экспонента
}

// PrivateKey представляет закрытый ключ RSA
type PrivateKey struct {
	PublicKey        // Встроенный открытый ключ
	D         *big.Int // Закрытая экспонента
	P         *big.Int // Простое число p
	Q         *big.Int // Простое число q
	Phi       *big.Int // Функция Эйлера φ(n) = (p-1)(q-1)
}
