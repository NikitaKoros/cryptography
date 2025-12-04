package primality

import (
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
)

// MillerRabinTest реализует тест простоты Миллера-Рабина
type MillerRabinTest struct {
	*BasePrimalityTest
}

// NewMillerRabinTest создает новый тест Миллера-Рабина
func NewMillerRabinTest() *MillerRabinTest {
	test := &MillerRabinTest{}
	test.BasePrimalityTest = NewBasePrimalityTest("Miller-Rabin", test.millerRabinIteration)
	return test
}

// millerRabinIteration выполняет одну итерацию теста Миллера-Рабина
// Алгоритм:
// 1. Представить n-1 как 2^s * d, где d нечетное
// 2. Вычислить a^d mod n
// 3. Проверить две условия:
//    - a^d ≡ 1 (mod n), или
//    - a^(2^r * d) ≡ -1 (mod n) для некоторого 0 ≤ r < s
func (m *MillerRabinTest) millerRabinIteration(n, a *big.Int) bool {
	ntService := numbertheory.NewService()

	// 1. Представить n-1 как 2^s * d
	s, d := m.factorPowerOfTwo(n)

	// 2. Вычислить x = a^d mod n
	x := ntService.ModExp(a, d, n)

	// Первая проверка: a^d ≡ 1 (mod n)
	if x.Cmp(big.NewInt(1)) == 0 {
		return true
	}

	// Вторая проверка: a^(2^r * d) ≡ -1 (mod n) для r = 0, 1, ..., s-1
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))

	for r := 0; r < s; r++ {
		if x.Cmp(nMinus1) == 0 {
			return true
		}

		// x = x^2 mod n
		x.Mul(x, x)
		x.Mod(x, n)
	}

	return false
}

// factorPowerOfTwo представляет n-1 как 2^s * d, где d нечетное
// Возвращает s и d
func (m *MillerRabinTest) factorPowerOfTwo(n *big.Int) (int, *big.Int) {
	d := new(big.Int).Sub(n, big.NewInt(1))
	s := 0

	// Делим d на 2, пока оно четное
	for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		d.Div(d, big.NewInt(2))
		s++
	}

	return s, d
}
