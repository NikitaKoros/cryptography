package numbertheory

import (
	"math/big"
	"testing"
)

func TestGCD(t *testing.T) {
	s := NewService()

	tests := []struct {
		a, b, expected *big.Int
	}{
		{big.NewInt(48), big.NewInt(18), big.NewInt(6)},
		{big.NewInt(100), big.NewInt(50), big.NewInt(50)},
		{big.NewInt(17), big.NewInt(19), big.NewInt(1)},
		{big.NewInt(0), big.NewInt(5), big.NewInt(5)},
	}

	for _, tt := range tests {
		result := s.GCD(tt.a, tt.b)
		if result.Cmp(tt.expected) != 0 {
			t.Errorf("GCD(%d, %d) = %d; expected %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestExtendedGCD(t *testing.T) {
	s := NewService()

	a := big.NewInt(240)
	b := big.NewInt(46)
	result := s.ExtendedGCD(a, b)

	// Проверяем соотношение Безу: a*x + b*y = gcd
	check := new(big.Int).Mul(a, result.X)
	temp := new(big.Int).Mul(b, result.Y)
	check.Add(check, temp)

	if check.Cmp(result.GCD) != 0 {
		t.Errorf("ExtendedGCD failed: %d*%d + %d*%d = %d, expected %d",
			a, result.X, b, result.Y, check, result.GCD)
	}
}

func TestLegendreSymbol(t *testing.T) {
	s := NewService()

	tests := []struct {
		a, p     *big.Int
		expected int
	}{
		{big.NewInt(7), big.NewInt(13), -1},
		{big.NewInt(1), big.NewInt(13), 1},
		{big.NewInt(4), big.NewInt(13), 1},
		{big.NewInt(13), big.NewInt(13), 0},
	}

	for _, tt := range tests {
		result := s.LegendreSymbol(tt.a, tt.p)
		if result != tt.expected {
			t.Errorf("LegendreSymbol(%d, %d) = %d; expected %d", tt.a, tt.p, result, tt.expected)
		}
	}
}

func TestJacobiSymbol(t *testing.T) {
	s := NewService()

	tests := []struct {
		a, n     *big.Int
		expected int
	}{
		{big.NewInt(2), big.NewInt(15), 1},
		{big.NewInt(3), big.NewInt(15), 0},
		{big.NewInt(1), big.NewInt(9), 1},
	}

	for _, tt := range tests {
		result := s.JacobiSymbol(tt.a, tt.n)
		if result != tt.expected {
			t.Errorf("JacobiSymbol(%d, %d) = %d; expected %d", tt.a, tt.n, result, tt.expected)
		}
	}
}

func TestModExp(t *testing.T) {
	s := NewService()

	tests := []struct {
		base, exp, mod, expected *big.Int
	}{
		{big.NewInt(3), big.NewInt(7), big.NewInt(13), big.NewInt(3)},
		{big.NewInt(2), big.NewInt(10), big.NewInt(1000), big.NewInt(24)},
		{big.NewInt(5), big.NewInt(3), big.NewInt(13), big.NewInt(8)},
	}

	for _, tt := range tests {
		result := s.ModExp(tt.base, tt.exp, tt.mod)
		if result.Cmp(tt.expected) != 0 {
			t.Errorf("ModExp(%d, %d, %d) = %d; expected %d",
				tt.base, tt.exp, tt.mod, result, tt.expected)
		}
	}
}
