package primality

import (
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
)

// FermatTest реализует тест простоты Ферма
type FermatTest struct {
	*BasePrimalityTest
}

// NewFermatTest создает новый тест Ферма
func NewFermatTest() *FermatTest {
	test := &FermatTest{}
	test.BasePrimalityTest = NewBasePrimalityTest("Fermat", test.fermatIteration)
	return test
}

// fermatIteration выполняет одну итерацию теста Ферма
// Проверяет условие: a^(n-1) ≡ 1 (mod n)
func (f *FermatTest) fermatIteration(n, a *big.Int) bool {
	ntService := numbertheory.NewService()

	// Проверяем gcd(a, n) = 1
	gcd := ntService.GCD(a, n)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return false // Если gcd != 1, число составное
	}

	// Вычисляем a^(n-1) mod n
	exp := new(big.Int).Sub(n, big.NewInt(1))
	result := ntService.ModExp(a, exp, n)

	// Проверяем равенство 1
	return result.Cmp(big.NewInt(1)) == 0
}
