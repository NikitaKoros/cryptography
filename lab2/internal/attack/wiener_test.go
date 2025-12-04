package attack

import (
	"math/big"
	"testing"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
)

func TestWienerAttack(t *testing.T) {
	// Создаем уязвимый RSA ключ с малым d
	p, _ := new(big.Int).SetString("160523347", 10)
	q, _ := new(big.Int).SetString("160584539", 10)
	n := new(big.Int).Mul(p, q)

	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	d, _ := new(big.Int).SetString("1009", 10)
	ntService := numbertheory.NewService()
	result := ntService.ExtendedGCD(d, phi)
	e := new(big.Int).Set(result.X)
	if e.Cmp(big.NewInt(0)) < 0 {
		e.Add(e, phi)
	}

	// Выполняем атаку
	wienerService := NewWienerService()
	attackResult, err := wienerService.Attack(e, n)

	if err != nil {
		t.Fatalf("Wiener attack failed: %v", err)
	}

	// Проверяем результаты
	if attackResult.D.Cmp(d) != 0 {
		t.Errorf("Found D = %d, expected %d", attackResult.D, d)
	}

	checkPQ := new(big.Int).Mul(attackResult.P, attackResult.Q)
	if checkPQ.Cmp(n) != 0 {
		t.Error("P * Q != N")
	}
}

func TestContinuedFraction(t *testing.T) {
	e := big.NewInt(7)
	N := big.NewInt(100)

	cf := ContinuedFraction(e, N)

	if len(cf) == 0 {
		t.Error("Continued fraction should not be empty")
	}
}

func TestConvergent(t *testing.T) {
	cf := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3)}

	k, d := Convergent(cf, 2)

	if k.Cmp(big.NewInt(0)) == 0 && d.Cmp(big.NewInt(1)) == 0 {
		t.Error("Convergent returned invalid values")
	}
}
