package attack

import "math/big"

// ContinuedFraction вычисляет цепную дробь для e/N
func ContinuedFraction(e, N *big.Int) []*big.Int {
	cf := []*big.Int{}
	num := new(big.Int).Set(e)
	den := new(big.Int).Set(N)

	for den.Cmp(big.NewInt(0)) != 0 {
		// a = num / den
		a := new(big.Int).Div(num, den)
		cf = append(cf, a)

		// temp = num - a * den
		temp := new(big.Int).Mul(a, den)
		temp.Sub(num, temp)

		// num, den = den, temp
		num.Set(den)
		den.Set(temp)
	}

	return cf
}

// Convergent вычисляет n-ую подходящую дробь для цепной дроби
// Возвращает числитель и знаменатель подходящей дроби
func Convergent(cf []*big.Int, n int) (*big.Int, *big.Int) {
	if n < 0 || n >= len(cf) {
		return big.NewInt(0), big.NewInt(1)
	}

	if n == 0 {
		return new(big.Int).Set(cf[0]), big.NewInt(1)
	}

	// Начальные значения
	hPrev2 := big.NewInt(1)
	hPrev1 := new(big.Int).Set(cf[0])
	kPrev2 := big.NewInt(0)
	kPrev1 := big.NewInt(1)

	for i := 1; i <= n; i++ {
		// h_i = a_i * h_{i-1} + h_{i-2}
		hCurr := new(big.Int).Mul(cf[i], hPrev1)
		hCurr.Add(hCurr, hPrev2)

		// k_i = a_i * k_{i-1} + k_{i-2}
		kCurr := new(big.Int).Mul(cf[i], kPrev1)
		kCurr.Add(kCurr, kPrev2)

		hPrev2.Set(hPrev1)
		hPrev1.Set(hCurr)
		kPrev2.Set(kPrev1)
		kPrev1.Set(kCurr)
	}

	return hPrev1, kPrev1
}

// ConvergentFraction представляет подходящую дробь k/d
type ConvergentFraction struct {
	K *big.Int // Числитель
	D *big.Int // Знаменатель
}
