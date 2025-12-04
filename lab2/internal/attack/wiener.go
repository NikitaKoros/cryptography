package attack

import (
	"fmt"
	"math/big"
)

// WienerAttackResult содержит результаты атаки Винера
type WienerAttackResult struct {
	D                   *big.Int              // Найденная закрытая экспонента d
	Phi                 *big.Int              // Функция Эйлера φ(n)
	P                   *big.Int              // Простое число p (если найдено)
	Q                   *big.Int              // Простое число q (если найдено)
	ConvergentFractions []*ConvergentFraction // Все вычисленные подходящие дроби
}

// WienerService предоставляет функционал для атаки Винера на RSA
type WienerService struct{}

// NewWienerService создает новый сервис атаки Винера
func NewWienerService() *WienerService {
	return &WienerService{}
}

// Attack выполняет атаку Винера на открытый ключ RSA
// Возвращает найденные значения d, φ(n), p, q и все подходящие дроби
func (ws *WienerService) Attack(e, N *big.Int) (*WienerAttackResult, error) {
	// Шаг 1: Разложить e/N в цепную дробь
	cf := ContinuedFraction(e, N)

	result := &WienerAttackResult{
		ConvergentFractions: make([]*ConvergentFraction, 0),
	}

	// Шаг 2-4: Перебрать все подходящие дроби
	for n := 0; n < len(cf); n++ {
		k, d := Convergent(cf, n)

		// Сохраняем подходящую дробь
		result.ConvergentFractions = append(result.ConvergentFractions, &ConvergentFraction{
			K: new(big.Int).Set(k),
			D: new(big.Int).Set(d),
		})

		// Пропускаем если k = 0
		if k.Cmp(big.NewInt(0)) == 0 {
			continue
		}

		// Шаг 3.1: Вычисляем phi_n = (e*d - 1) / k
		edMinus1 := new(big.Int).Mul(e, d)
		edMinus1.Sub(edMinus1, big.NewInt(1))

		if new(big.Int).Mod(edMinus1, k).Cmp(big.NewInt(0)) != 0 {
			continue
		}

		phiN := new(big.Int).Div(edMinus1, k)

		// Шаг 3.2: Решаем уравнение x^2 - ((N - phi_n) + 1)x + N = 0
		// x^2 - bx + c = 0, где b = N - phi_n + 1, c = N
		b := new(big.Int).Sub(N, phiN)
		b.Add(b, big.NewInt(1))
		c := new(big.Int).Set(N)

		p, q, ok := ws.solveQuadratic(b, c)
		if !ok {
			continue
		}

		// Шаг 4: Проверяем, что p * q = N
		pq := new(big.Int).Mul(p, q)
		if pq.Cmp(N) == 0 {
			result.D = d
			result.Phi = phiN
			result.P = p
			result.Q = q
			return result, nil
		}
	}

	return nil, fmt.Errorf("атака Винера не удалась: закрытая экспонента d слишком велика или ключ защищен")
}

// solveQuadratic решает квадратное уравнение x^2 - bx + c = 0
// Возвращает два корня и флаг успеха
func (ws *WienerService) solveQuadratic(b, c *big.Int) (*big.Int, *big.Int, bool) {
	// Дискриминант: D = b^2 - 4c
	D := new(big.Int).Mul(b, b)
	fourC := new(big.Int).Mul(big.NewInt(4), c)
	D.Sub(D, fourC)

	if D.Cmp(big.NewInt(0)) < 0 {
		return nil, nil, false
	}

	// Проверяем, является ли D полным квадратом
	sqrtD := new(big.Int).Sqrt(D)
	if new(big.Int).Mul(sqrtD, sqrtD).Cmp(D) != 0 {
		return nil, nil, false
	}

	// x1 = (b + sqrt(D)) / 2
	x1 := new(big.Int).Add(b, sqrtD)
	if new(big.Int).Mod(x1, big.NewInt(2)).Cmp(big.NewInt(0)) != 0 {
		return nil, nil, false
	}
	x1.Div(x1, big.NewInt(2))

	// x2 = (b - sqrt(D)) / 2
	x2 := new(big.Int).Sub(b, sqrtD)
	if new(big.Int).Mod(x2, big.NewInt(2)).Cmp(big.NewInt(0)) != 0 {
		return nil, nil, false
	}
	x2.Div(x2, big.NewInt(2))

	return x1, x2, true
}

// AttackPublicKey - удобная обертка для атаки на открытый ключ
func (ws *WienerService) AttackPublicKey(e, N *big.Int) (*WienerAttackResult, error) {
	return ws.Attack(e, N)
}
