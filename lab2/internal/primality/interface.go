package primality

import "math/big"

// PrimalityTester предоставляет интерфейс для вероятностных тестов простоты
type PrimalityTester interface {
	// IsProbablyPrime выполняет вероятностный тест простоты
	// n - тестируемое значение
	// minProbability - минимальная вероятность простоты в диапазоне [0.5, 1)
	// Возвращает true если число вероятно простое, false если точно составное
	IsProbablyPrime(n *big.Int, minProbability float64) bool

	// GetName возвращает название теста
	GetName() string
}
