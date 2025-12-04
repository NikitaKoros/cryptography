package primality

import (
	"math/big"
	"testing"
)

func TestFermatTest(t *testing.T) {
	test := NewFermatTest()

	primes := []*big.Int{
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(5),
		big.NewInt(7),
		big.NewInt(11),
		big.NewInt(17),
		big.NewInt(23),
	}

	composites := []*big.Int{
		big.NewInt(4),
		big.NewInt(6),
		big.NewInt(8),
		big.NewInt(9),
		big.NewInt(10),
		big.NewInt(15),
	}

	minProbability := 0.99

	for _, p := range primes {
		if !test.IsProbablyPrime(p, minProbability) {
			t.Errorf("Fermat: %d should be prime", p)
		}
	}

	for _, c := range composites {
		if test.IsProbablyPrime(c, minProbability) {
			t.Errorf("Fermat: %d should be composite", c)
		}
	}
}

func TestSolovayStrassenTest(t *testing.T) {
	test := NewSolovayStrassenTest()

	primes := []*big.Int{
		big.NewInt(17),
		big.NewInt(23),
		big.NewInt(29),
	}

	composites := []*big.Int{
		big.NewInt(15),
		big.NewInt(21),
		big.NewInt(25),
	}

	minProbability := 0.99

	for _, p := range primes {
		if !test.IsProbablyPrime(p, minProbability) {
			t.Errorf("Solovay-Strassen: %d should be prime", p)
		}
	}

	for _, c := range composites {
		if test.IsProbablyPrime(c, minProbability) {
			t.Errorf("Solovay-Strassen: %d should be composite", c)
		}
	}
}

func TestMillerRabinTest(t *testing.T) {
	test := NewMillerRabinTest()

	primes := []*big.Int{
		big.NewInt(17),
		big.NewInt(23),
		big.NewInt(29),
		big.NewInt(97),
	}

	composites := []*big.Int{
		big.NewInt(15),
		big.NewInt(21),
		big.NewInt(25),
		big.NewInt(561), // Псевдопростое Ферма
	}

	minProbability := 0.99

	for _, p := range primes {
		if !test.IsProbablyPrime(p, minProbability) {
			t.Errorf("Miller-Rabin: %d should be prime", p)
		}
	}

	for _, c := range composites {
		if test.IsProbablyPrime(c, minProbability) {
			t.Errorf("Miller-Rabin: %d should be composite", c)
		}
	}
}
