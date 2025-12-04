package primality

import (
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
)

// SolovayStrassenTest реализует тест простоты Соловея-Штрассена
type SolovayStrassenTest struct {
	*BasePrimalityTest
}

// NewSolovayStrassenTest создает новый тест Соловея-Штрассена
func NewSolovayStrassenTest() *SolovayStrassenTest {
	test := &SolovayStrassenTest{}
	test.BasePrimalityTest = NewBasePrimalityTest("Solovay-Strassen", test.solovayStrassenIteration)
	return test
}

// solovayStrassenIteration выполняет одну итерацию теста Соловея-Штрассена
// Алгоритм:
// 1. Проверяем gcd(a, n) = 1
// 2. Вычисляем j = a^((n-1)/2) mod n
// 3. Вычисляем символ Якоби J(a, n)
// 4. Если j != J(a, n) mod n, то число составное
func (s *SolovayStrassenTest) solovayStrassenIteration(n, a *big.Int) bool {
	ntService := numbertheory.NewService()

	// 1. Проверяем gcd(a, n) = 1
	gcd := ntService.GCD(a, n)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return false // Число составное
	}

	// 2. Вычисляем j = a^((n-1)/2) mod n
	exp := new(big.Int).Sub(n, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))
	j := ntService.ModExp(a, exp, n)

	// 3. Вычисляем символ Якоби J(a, n)
	jacobi := ntService.JacobiSymbol(a, n)

	// Преобразуем символ Якоби в число mod n
	jacobiMod := big.NewInt(int64(jacobi))
	if jacobiMod.Cmp(big.NewInt(0)) < 0 {
		// -1 mod n = n - 1
		jacobiMod.Add(jacobiMod, n)
	}

	// 4. Проверяем j == J(a, n) mod n
	return j.Cmp(jacobiMod) == 0
}
