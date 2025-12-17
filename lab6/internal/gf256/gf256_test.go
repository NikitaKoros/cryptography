package gf256

import (
	"testing"
)

// Тест создания GF256 с корректным модулем
func TestNewGF256_ValidModulus(t *testing.T) {
	validModuli := []byte{0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F}

	for _, modulus := range validModuli {
		gf, err := NewGF256(modulus)
		if err != nil {
			t.Errorf("NewGF256(0x%02X) вернул ошибку: %v", modulus, err)
		}
		if gf == nil {
			t.Errorf("NewGF256(0x%02X) вернул nil", modulus)
		}
		if gf.modulus != modulus {
			t.Errorf("NewGF256(0x%02X): ожидалось modulus = 0x%02X, получено 0x%02X",
				modulus, modulus, gf.modulus)
		}
	}
}

// Тест создания GF256 с неприводимым модулем
func TestNewGF256_InvalidModulus(t *testing.T) {
	// Приводимые полиномы
	invalidModuli := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20}

	for _, modulus := range invalidModuli {
		gf, err := NewGF256(modulus)
		if err == nil {
			t.Errorf("NewGF256(0x%02X) должен был вернуть ошибку для приводимого модуля", modulus)
		}
		if gf != nil {
			t.Errorf("NewGF256(0x%02X) должен был вернуть nil для приводимого модуля", modulus)
		}
	}
}

// Тест сложения в GF(2^8)
func TestAdd(t *testing.T) {
	tests := []struct {
		a, b, expected byte
	}{
		{0x00, 0x00, 0x00}, // 0 + 0 = 0
		{0x01, 0x00, 0x01}, // 1 + 0 = 1
		{0x00, 0x01, 0x01}, // 0 + 1 = 1
		{0x01, 0x01, 0x00}, // 1 + 1 = 0 (XOR)
		{0xFF, 0xFF, 0x00}, // FF + FF = 0
		{0x53, 0xCA, 0x99}, // Произвольные значения
		{0xAA, 0x55, 0xFF}, // 10101010 XOR 01010101 = 11111111
	}

	for _, tt := range tests {
		result := Add(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("Add(0x%02X, 0x%02X) = 0x%02X; ожидалось 0x%02X",
				tt.a, tt.b, result, tt.expected)
		}
	}
}

// Тест коммутативности сложения
func TestAdd_Commutative(t *testing.T) {
	testValues := []byte{0x00, 0x01, 0x53, 0xCA, 0xFF}

	for _, a := range testValues {
		for _, b := range testValues {
			if Add(a, b) != Add(b, a) {
				t.Errorf("Сложение не коммутативно: Add(0x%02X, 0x%02X) != Add(0x%02X, 0x%02X)",
					a, b, b, a)
			}
		}
	}
}

// Тест умножения в GF(2^8)
func TestMultiply(t *testing.T) {
	gf, _ := NewGF256(0x1B) // x^8 + x^4 + x^3 + x + 1 (стандартный AES)

	tests := []struct {
		a, b, expected byte
	}{
		{0x00, 0x00, 0x00}, // 0 * 0 = 0
		{0x01, 0x00, 0x00}, // 1 * 0 = 0
		{0x00, 0x01, 0x00}, // 0 * 1 = 0
		{0x01, 0x01, 0x01}, // 1 * 1 = 1
		{0x01, 0x53, 0x53}, // 1 * x = x
		{0x02, 0x01, 0x02}, // x * 1 = x
		{0x02, 0x02, 0x04}, // x * x = x^2
		{0x02, 0x80, 0x1B}, // x * x^7 = x^8 mod (x^8 + x^4 + x^3 + x + 1) = x^4 + x^3 + x + 1
		{0x53, 0xCA, 0x01}, // Из примера в main.go
	}

	for _, tt := range tests {
		result := gf.Multiply(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("Multiply(0x%02X, 0x%02X) = 0x%02X; ожидалось 0x%02X",
				tt.a, tt.b, result, tt.expected)
		}
	}
}

// Тест коммутативности умножения
func TestMultiply_Commutative(t *testing.T) {
	gf, _ := NewGF256(0x1B)
	testValues := []byte{0x00, 0x01, 0x02, 0x53, 0xCA, 0xFF}

	for _, a := range testValues {
		for _, b := range testValues {
			if gf.Multiply(a, b) != gf.Multiply(b, a) {
				t.Errorf("Умножение не коммутативно: Multiply(0x%02X, 0x%02X) != Multiply(0x%02X, 0x%02X)",
					a, b, b, a)
			}
		}
	}
}

// Тест дистрибутивности умножения относительно сложения
func TestMultiply_Distributive(t *testing.T) {
	gf, _ := NewGF256(0x1B)
	testValues := []byte{0x02, 0x03, 0x05}

	for _, a := range testValues {
		for _, b := range testValues {
			for _, c := range testValues {
				// a * (b + c) = a * b + a * c
				left := gf.Multiply(a, Add(b, c))
				right := Add(gf.Multiply(a, b), gf.Multiply(a, c))
				if left != right {
					t.Errorf("Дистрибутивность не выполняется для a=0x%02X, b=0x%02X, c=0x%02X", a, b, c)
				}
			}
		}
	}
}

// Тест обратного элемента
func TestInverse(t *testing.T) {
	gf, _ := NewGF256(0x1B)

	// Тест обратного для 0 (должна быть ошибка)
	_, err := gf.Inverse(0x00)
	if err == nil {
		t.Error("Inverse(0x00) должен возвращать ошибку")
	}

	// Тест обратного для 1
	inv, err := gf.Inverse(0x01)
	if err != nil {
		t.Errorf("Inverse(0x01) вернул ошибку: %v", err)
	}
	if inv != 0x01 {
		t.Errorf("Inverse(0x01) = 0x%02X; ожидалось 0x01", inv)
	}

	// Тест что a * a^-1 = 1 для всех ненулевых элементов
	for a := byte(1); a != 0; a++ {
		inv, err := gf.Inverse(a)
		if err != nil {
			t.Errorf("Inverse(0x%02X) вернул ошибку: %v", a, err)
			continue
		}

		product := gf.Multiply(a, inv)
		if product != 0x01 {
			t.Errorf("0x%02X * Inverse(0x%02X) = 0x%02X; ожидалось 0x01",
				a, a, product)
		}
	}
}

// Тест XTime
func TestXTime(t *testing.T) {
	gf, _ := NewGF256(0x1B)

	tests := []struct {
		input, expected byte
	}{
		{0x00, 0x00},
		{0x01, 0x02}, // x * 1 = x
		{0x02, 0x04}, // x * x = x^2
		{0x40, 0x80}, // x * x^6 = x^7
		{0x80, 0x1B}, // x * x^7 = x^8 mod (x^8 + x^4 + x^3 + x + 1) = x^4 + x^3 + x + 1
		{0x57, 0xAE},
		{0xAE, 0x47},
	}

	for _, tt := range tests {
		result := gf.XTime(tt.input)
		if result != tt.expected {
			t.Errorf("XTime(0x%02X) = 0x%02X; ожидалось 0x%02X",
				tt.input, result, tt.expected)
		}

		// XTime(a) должно быть равно Multiply(0x02, a)
		mult := gf.Multiply(0x02, tt.input)
		if result != mult {
			t.Errorf("XTime(0x%02X) != Multiply(0x02, 0x%02X): 0x%02X != 0x%02X",
				tt.input, tt.input, result, mult)
		}
	}
}

// Тест проверки неприводимости
func TestIsIrreducible(t *testing.T) {
	// Известные неприводимые полиномы степени 8
	irreducible := []byte{
		0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F, 0x4D, 0x5F, 0x63, 0x65,
	}

	for _, poly := range irreducible {
		if !IsIrreducible(poly) {
			t.Errorf("IsIrreducible(0x%02X) = false; ожидалось true", poly)
		}
	}

	// Известные приводимые полиномы
	reducible := []byte{
		0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x10, 0x12, 0x20,
	}

	for _, poly := range reducible {
		if IsIrreducible(poly) {
			t.Errorf("IsIrreducible(0x%02X) = true; ожидалось false", poly)
		}
	}
}

// Тест получения всех неприводимых полиномов
func TestGetAllIrreduciblePolynomials(t *testing.T) {
	polys := GetAllIrreduciblePolynomials()

	// Должно быть ровно 30 неприводимых полиномов степени 8
	expectedCount := 30
	if len(polys) != expectedCount {
		t.Errorf("GetAllIrreduciblePolynomials() вернул %d полиномов; ожидалось %d",
			len(polys), expectedCount)
	}

	// Все должны быть неприводимыми
	for _, poly := range polys {
		if !IsIrreducible(poly) {
			t.Errorf("Полином 0x%02X в списке неприводимых, но не проходит проверку IsIrreducible", poly)
		}
	}

	// Не должно быть дубликатов
	seen := make(map[byte]bool)
	for _, poly := range polys {
		if seen[poly] {
			t.Errorf("Дубликат полинома 0x%02X в результате GetAllIrreduciblePolynomials", poly)
		}
		seen[poly] = true
	}
}

// Тест факторизации полинома
func TestFactorPolynomial(t *testing.T) {
	tests := []struct {
		poly     uint64
		expected []uint64
	}{
		{0, []uint64{}},                      // 0 не имеет множителей
		{1, []uint64{}},                      // 1 не имеет множителей
		{2, []uint64{2}},                     // x - простой
		{3, []uint64{3}},                     // x + 1 - простой
		{4, []uint64{2, 2}},                  // x^2 = x * x
		{6, []uint64{2, 3}},                  // (x + 1) * x = x^2 + x
		{0b110110110, []uint64{2, 3, 73}},    // Из примера в main.go
	}

	for _, tt := range tests {
		result := FactorPolynomial(tt.poly)
		if len(result) != len(tt.expected) {
			t.Errorf("FactorPolynomial(0b%b): получено %d множителей, ожидалось %d",
				tt.poly, len(result), len(tt.expected))
			continue
		}

		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("FactorPolynomial(0b%b)[%d] = %d; ожидалось %d",
					tt.poly, i, result[i], tt.expected[i])
			}
		}
	}
}

// Тест degree
func TestDegree(t *testing.T) {
	tests := []struct {
		poly     uint16
		expected int
	}{
		{0x0000, -1},
		{0x0001, 0},
		{0x0002, 1},
		{0x0004, 2},
		{0x0008, 3},
		{0x0010, 4},
		{0x0080, 7},
		{0x0100, 8},
		{0x01FF, 8},
		{0xFFFF, 15},
	}

	for _, tt := range tests {
		result := degree(tt.poly)
		if result != tt.expected {
			t.Errorf("degree(0x%04X) = %d; ожидалось %d", tt.poly, result, tt.expected)
		}
	}
}

// Тест ElementToString
func TestElementToString(t *testing.T) {
	tests := []struct {
		elem     byte
		expected string
	}{
		{0x00, "0x00"},
		{0x01, "0x01"},
		{0x1B, "0x1B"},
		{0xFF, "0xFF"},
	}

	for _, tt := range tests {
		result := ElementToString(tt.elem)
		if result != tt.expected {
			t.Errorf("ElementToString(0x%02X) = %s; ожидалось %s",
				tt.elem, result, tt.expected)
		}
	}
}

// Тест PolyToString
func TestPolyToString(t *testing.T) {
	tests := []struct {
		poly     byte
		contains []string // подстроки, которые должны присутствовать
	}{
		{0x00, []string{"x^8"}},                                   // x^8
		{0x01, []string{"x^8", "1"}},                              // x^8 + 1
		{0x1B, []string{"x^8", "x^4", "x^3", "x", "1"}},           // x^8 + x^4 + x^3 + x + 1
		{0xFF, []string{"x^8", "x^7", "x^6", "x^5", "x^4", "x^3", "x^2", "x", "1"}}, // все члены
	}

	for _, tt := range tests {
		result := PolyToString(tt.poly)
		for _, substr := range tt.contains {
			if !contains(result, substr) {
				t.Errorf("PolyToString(0x%02X) = %s; ожидалось наличие подстроки %s",
					tt.poly, result, substr)
			}
		}
	}
}

// Вспомогательная функция для проверки наличия подстроки
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Бенчмарк для умножения
func BenchmarkMultiply(b *testing.B) {
	gf, _ := NewGF256(0x1B)
	a, x := byte(0x53), byte(0xCA)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gf.Multiply(a, x)
	}
}

// Бенчмарк для обратного элемента
func BenchmarkInverse(b *testing.B) {
	gf, _ := NewGF256(0x1B)
	a := byte(0x53)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gf.Inverse(a)
	}
}

// Бенчмарк для проверки неприводимости
func BenchmarkIsIrreducible(b *testing.B) {
	poly := byte(0x1B)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsIrreducible(poly)
	}
}
