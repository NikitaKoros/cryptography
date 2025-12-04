package rsa

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
	"github.com/nikitakorostin/cryptography/lab2/internal/primality"
)

// KeyGenerator вложенный сервис для генерации ключей RSA
type KeyGenerator struct {
	testType       TestType
	minProbability float64
	bitLength      int
	primalityTest  primality.PrimalityTester
	ntService      *numbertheory.Service
}

// NewKeyGenerator создает новый генератор ключей
func NewKeyGenerator(testType TestType, minProbability float64, bitLength int) *KeyGenerator {
	// Выбираем тест простоты
	var test primality.PrimalityTester
	switch testType {
	case TestTypeFermat:
		test = primality.NewFermatTest()
	case TestTypeSolovayStrassen:
		test = primality.NewSolovayStrassenTest()
	case TestTypeMillerRabin:
		test = primality.NewMillerRabinTest()
	default:
		test = primality.NewMillerRabinTest()
	}

	return &KeyGenerator{
		testType:       testType,
		minProbability: minProbability,
		bitLength:      bitLength,
		primalityTest:  test,
		ntService:      numbertheory.NewService(),
	}
}

// GenerateKeyPair генерирует новую пару ключей RSA
// Обеспечивает защиту от атаки Ферма и атаки Винера
func (kg *KeyGenerator) GenerateKeyPair() (*PrivateKey, error) {
	maxAttempts := 1000

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Генерируем два простых числа p и q
		p, err := kg.generatePrime()
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации p: %w", err)
		}

		q, err := kg.generatePrime()
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации q: %w", err)
		}

		// Защита от атаки Ферма: |p - q| > 2^(bitLength/4)
		if !kg.checkFermatProtection(p, q) {
			continue
		}

		// Вычисляем n = p * q
		n := new(big.Int).Mul(p, q)

		// Вычисляем φ(n) = (p-1)(q-1)
		pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
		phi := new(big.Int).Mul(pMinus1, qMinus1)

		// Выбираем открытую экспоненту e
		e := big.NewInt(65537) // Стандартное значение

		// Проверяем gcd(e, φ(n)) = 1
		gcd := kg.ntService.GCD(e, phi)
		if gcd.Cmp(big.NewInt(1)) != 0 {
			continue
		}

		// Вычисляем закрытую экспоненту d: d ≡ e^(-1) (mod φ(n))
		result := kg.ntService.ExtendedGCD(e, phi)
		d := new(big.Int).Set(result.X)

		// Нормализуем d в положительное значение
		if d.Cmp(big.NewInt(0)) < 0 {
			d.Add(d, phi)
		}

		// Защита от атаки Винера: d > N^(1/4) / 3
		if !kg.checkWienerProtection(d, n) {
			continue
		}

		// Создаем ключи
		privateKey := &PrivateKey{
			PublicKey: PublicKey{
				N: n,
				E: e,
			},
			D:   d,
			P:   p,
			Q:   q,
			Phi: phi,
		}

		return privateKey, nil
	}

	return nil, fmt.Errorf("не удалось сгенерировать безопасные ключи за %d попыток", maxAttempts)
}

// generatePrime генерирует простое число заданной битовой длины
func (kg *KeyGenerator) generatePrime() (*big.Int, error) {
	maxAttempts := 10000

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Генерируем случайное число нужной битовой длины
		candidate, err := rand.Prime(rand.Reader, kg.bitLength)
		if err != nil {
			return nil, err
		}

		// Проверяем на простоту нашим тестом
		if kg.primalityTest.IsProbablyPrime(candidate, kg.minProbability) {
			return candidate, nil
		}
	}

	return nil, fmt.Errorf("не удалось сгенерировать простое число за %d попыток", maxAttempts)
}

// checkFermatProtection проверяет защиту от атаки Ферма
// Условие: |p - q| > 2^(bitLength/4)
func (kg *KeyGenerator) checkFermatProtection(p, q *big.Int) bool {
	diff := new(big.Int).Sub(p, q)
	diff.Abs(diff)

	minDiff := new(big.Int).Lsh(big.NewInt(1), uint(kg.bitLength/4))
	return diff.Cmp(minDiff) > 0
}

// checkWienerProtection проверяет защиту от атаки Винера
// Условие: d > N^(1/4) / 3
func (kg *KeyGenerator) checkWienerProtection(d, n *big.Int) bool {
	// Вычисляем N^(1/4) методом Ньютона
	root := kg.nthRoot(n, 4)

	// Минимальное значение: N^(1/4) / 3
	minD := new(big.Int).Div(root, big.NewInt(3))

	return d.Cmp(minD) > 0
}

// nthRoot вычисляет целый n-й корень из x методом Ньютона
func (kg *KeyGenerator) nthRoot(x *big.Int, n int) *big.Int {
	if x.Cmp(big.NewInt(0)) <= 0 {
		return big.NewInt(0)
	}

	// Начальное приближение
	guess := new(big.Int).Div(x, big.NewInt(2))
	nBig := big.NewInt(int64(n))
	nMinus1 := big.NewInt(int64(n - 1))

	// Итерации метода Ньютона
	for i := 0; i < 100; i++ {
		// guess_new = ((n-1) * guess + x / guess^(n-1)) / n
		pow := new(big.Int).Exp(guess, nMinus1, nil)
		term1 := new(big.Int).Mul(nMinus1, guess)
		term2 := new(big.Int).Div(x, pow)
		guessNew := new(big.Int).Add(term1, term2)
		guessNew.Div(guessNew, nBig)

		// Проверка сходимости
		if guessNew.Cmp(guess) >= 0 {
			break
		}

		guess = guessNew
	}

	return guess
}
