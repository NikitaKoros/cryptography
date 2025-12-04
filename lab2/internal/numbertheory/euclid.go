package numbertheory

import "math/big"

// GCD вычисляет НОД двух целых чисел алгоритмом Евклида
func (s *Service) GCD(a, b *big.Int) *big.Int {
	// Создаем копии для работы
	x := new(big.Int).Set(a)
	y := new(big.Int).Set(b)

	// Работаем с абсолютными значениями
	x.Abs(x)
	y.Abs(y)

	// Алгоритм Евклида
	for y.Cmp(big.NewInt(0)) != 0 {
		temp := new(big.Int).Set(y)
		y.Mod(x, y)
		x.Set(temp)
	}

	return x
}

// ExtendedGCDResult содержит результаты расширенного алгоритма Евклида
type ExtendedGCDResult struct {
	GCD *big.Int // НОД(a, b)
	X   *big.Int // коэффициент x в уравнении Безу: ax + by = gcd(a,b)
	Y   *big.Int // коэффициент y в уравнении Безу: ax + by = gcd(a,b)
}

// ExtendedGCD вычисляет НОД и решает соотношение Безу
// Возвращает gcd, x, y такие что: a*x + b*y = gcd(a, b)
func (srv *Service) ExtendedGCD(a, b *big.Int) *ExtendedGCDResult {
	// Инициализация
	oldR, r := new(big.Int).Set(a), new(big.Int).Set(b)
	oldS, s := big.NewInt(1), big.NewInt(0)
	oldT, t := big.NewInt(0), big.NewInt(1)

	// Расширенный алгоритм Евклида
	for r.Cmp(big.NewInt(0)) != 0 {
		quotient := new(big.Int).Div(oldR, r)

		// oldR, r = r, oldR - quotient * r
		temp := new(big.Int).Set(r)
		r.Mul(quotient, r)
		r.Sub(oldR, r)
		oldR.Set(temp)

		// oldS, s = s, oldS - quotient * s
		temp = new(big.Int).Set(s)
		s.Mul(quotient, s)
		s.Sub(oldS, s)
		oldS.Set(temp)

		// oldT, t = t, oldT - quotient * t
		temp = new(big.Int).Set(t)
		t.Mul(quotient, t)
		t.Sub(oldT, t)
		oldT.Set(temp)
	}

	return &ExtendedGCDResult{
		GCD: oldR,
		X:   oldS,
		Y:   oldT,
	}
}
