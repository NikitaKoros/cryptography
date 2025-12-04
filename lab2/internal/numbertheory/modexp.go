package numbertheory

import "math/big"

// ModExp выполняет возведение в степень по модулю: base^exp mod m
// Использует алгоритм быстрого возведения в степень (бинарное возведение)
func (s *Service) ModExp(base, exp, m *big.Int) *big.Int {
	result := big.NewInt(1)
	base = new(big.Int).Mod(base, m)
	exp = new(big.Int).Set(exp)

	// Алгоритм быстрого возведения в степень
	for exp.Cmp(big.NewInt(0)) > 0 {
		// Если exp нечетное
		if new(big.Int).Mod(exp, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
			result.Mul(result, base)
			result.Mod(result, m)
		}

		// exp = exp / 2
		exp.Div(exp, big.NewInt(2))

		// base = base^2 mod m
		base.Mul(base, base)
		base.Mod(base, m)
	}

	return result
}
