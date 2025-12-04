package numbertheory

import "math/big"

// LegendreSymbol вычисляет символ Лежандра (a/p)
// Возвращает:
//   1 если a - квадратичный вычет по модулю p
//   -1 если a - квадратичный невычет по модулю p
//   0 если a делится на p
func (s *Service) LegendreSymbol(a, p *big.Int) int {
	// Вычисляем a^((p-1)/2) mod p
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(2))

	result := s.ModExp(a, exp, p)

	// Нормализуем результат к -1, 0, 1
	if result.Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	if result.Cmp(big.NewInt(1)) == 0 {
		return 1
	}

	// Если result > 1, то это p-1, что эквивалентно -1
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	if result.Cmp(pMinus1) == 0 {
		return -1
	}

	return 0
}

// JacobiSymbol вычисляет символ Якоби (a/n)
// Символ Якоби - обобщение символа Лежандра для составных чисел
// Если n = p1^k1 * p2^k2 * ... * pm^km, то (a/n) = (a/p1)^k1 * (a/p2)^k2 * ... * (a/pm)^km
func (s *Service) JacobiSymbol(a, n *big.Int) int {
	// Копируем значения
	a = new(big.Int).Set(a)
	n = new(big.Int).Set(n)

	// Проверка на корректность входных данных
	if n.Cmp(big.NewInt(0)) <= 0 || new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	a.Mod(a, n)
	result := 1

	for a.Cmp(big.NewInt(0)) != 0 {
		// Убираем все степени двойки из a
		for new(big.Int).Mod(a, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			a.Div(a, big.NewInt(2))

			// Применяем правило для (2/n)
			nMod8 := new(big.Int).Mod(n, big.NewInt(8))
			if nMod8.Cmp(big.NewInt(3)) == 0 || nMod8.Cmp(big.NewInt(5)) == 0 {
				result = -result
			}
		}

		// Меняем местами a и n
		a, n = n, a

		// Применяем закон квадратичной взаимности
		aMod4 := new(big.Int).Mod(a, big.NewInt(4))
		nMod4 := new(big.Int).Mod(n, big.NewInt(4))

		if aMod4.Cmp(big.NewInt(3)) == 0 && nMod4.Cmp(big.NewInt(3)) == 0 {
			result = -result
		}

		a.Mod(a, n)
	}

	if n.Cmp(big.NewInt(1)) == 0 {
		return result
	}

	return 0
}
