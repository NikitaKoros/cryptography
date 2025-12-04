package primality

import (
	"crypto/rand"
	"math"
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
)

// BasePrimalityTest реализует базовый класс для вероятностных тестов простоты
// Использует паттерн "Шаблонный метод" (Template Method)
type BasePrimalityTest struct {
	ntService     *numbertheory.Service
	name          string
	iterationFunc func(n, a *big.Int) bool // Кастомизируемая функция одной итерации
}

// NewBasePrimalityTest создает базовый тест простоты
func NewBasePrimalityTest(name string, iterationFunc func(n, a *big.Int) bool) *BasePrimalityTest {
	return &BasePrimalityTest{
		ntService:     numbertheory.NewService(),
		name:          name,
		iterationFunc: iterationFunc,
	}
}

// IsProbablyPrime выполняет вероятностный тест простоты (Template Method)
func (b *BasePrimalityTest) IsProbablyPrime(n *big.Int, minProbability float64) bool {
	// Валидация входных параметров
	if minProbability < 0.5 || minProbability >= 1.0 {
		panic("minProbability должна быть в диапазоне [0.5, 1)")
	}

	// Базовые проверки
	result := b.preCheck(n)
	if result == false {
		return false
	}

	// Для малых простых чисел (2, 3) и чисел <= 3 сразу возвращаем результат preCheck
	if n.Cmp(big.NewInt(3)) <= 0 {
		return result
	}

	// Вычисляем количество итераций для достижения требуемой вероятности
	iterations := b.calculateIterations(minProbability)

	// Выполняем итерации теста
	for i := 0; i < iterations; i++ {
		a := b.generateRandomBase(n)
		if !b.iterationFunc(n, a) {
			return false // Число точно составное
		}
	}

	return true // Число вероятно простое
}

// GetName возвращает название теста
func (b *BasePrimalityTest) GetName() string {
	return b.name
}

// preCheck выполняет базовые проверки перед тестом
func (b *BasePrimalityTest) preCheck(n *big.Int) bool {
	// n должно быть больше 1
	if n.Cmp(big.NewInt(1)) <= 0 {
		return false
	}

	// Специальная обработка для 2 и 3
	if n.Cmp(big.NewInt(2)) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true
	}

	// Проверка на четность
	if new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// Проверка малых простых чисел
	smallPrimes := []int64{5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}
	for _, p := range smallPrimes {
		prime := big.NewInt(p)
		if n.Cmp(prime) == 0 {
			return true
		}
		if new(big.Int).Mod(n, prime).Cmp(big.NewInt(0)) == 0 {
			return false
		}
	}

	return true
}

// calculateIterations вычисляет количество итераций для достижения требуемой вероятности
// Вероятность ошибки: (1/2)^k, где k - количество итераций
// Вероятность правильности: 1 - (1/2)^k >= minProbability
func (b *BasePrimalityTest) calculateIterations(minProbability float64) int {
	// 1 - (1/2)^k >= minProbability
	// (1/2)^k <= 1 - minProbability
	// k >= log2(1 / (1 - minProbability))
	errorProbability := 1.0 - minProbability
	iterations := int(math.Ceil(math.Log2(1.0 / errorProbability)))

	// Минимум 5 итераций для надежности
	if iterations < 5 {
		iterations = 5
	}

	return iterations
}

// generateRandomBase генерирует случайное число a в диапазоне [2, n-2]
func (b *BasePrimalityTest) generateRandomBase(n *big.Int) *big.Int {
	// Для малых чисел (n <= 4) возвращаем 2
	if n.Cmp(big.NewInt(4)) <= 0 {
		return big.NewInt(2)
	}

	// Генерируем случайное число в диапазоне [0, n-3]
	nMinus3 := new(big.Int).Sub(n, big.NewInt(3))
	a, _ := rand.Int(rand.Reader, nMinus3)

	// Смещаем в диапазон [2, n-2]
	a.Add(a, big.NewInt(2))

	return a
}
