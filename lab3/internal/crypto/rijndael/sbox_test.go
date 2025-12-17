package rijndael

import (
	"testing"
)

// Тест создания S-box с корректным модулем
func TestNewSBox_ValidModulus(t *testing.T) {
	validModuli := []byte{0x1B, 0x1D, 0x2B}

	for _, modulus := range validModuli {
		sbox, err := NewSBox(modulus)
		if err != nil {
			t.Errorf("NewSBox(0x%02X) вернул ошибку: %v", modulus, err)
		}
		if sbox == nil {
			t.Errorf("NewSBox(0x%02X) вернул nil", modulus)
		}
	}
}

// Тест создания S-box с некорректным модулем
func TestNewSBox_InvalidModulus(t *testing.T) {
	invalidModuli := []byte{0x00, 0x02, 0x04, 0x10}

	for _, modulus := range invalidModuli {
		sbox, err := NewSBox(modulus)
		if err == nil {
			t.Errorf("NewSBox(0x%02X) должен был вернуть ошибку для приводимого модуля", modulus)
		}
		if sbox != nil {
			t.Errorf("NewSBox(0x%02X) должен был вернуть nil", modulus)
		}
	}
}

// Тест что прямая и обратная S-box являются взаимно обратными
func TestSBox_ForwardInverse(t *testing.T) {
	sbox, err := NewSBox(0x1B)
	if err != nil {
		t.Fatalf("Не удалось создать S-box: %v", err)
	}

	for i := 0; i < 256; i++ {
		input := byte(i)
		forward := sbox.forward[input]
		inverse := sbox.inverse[forward]

		if inverse != input {
			t.Errorf("S-box не взаимно обратна для 0x%02X: forward=0x%02X, inverse=0x%02X",
				input, forward, inverse)
		}
	}
}

// Тест что обратная и прямая S-box являются взаимно обратными (в обратном направлении)
func TestSBox_InverseForward(t *testing.T) {
	sbox, err := NewSBox(0x1B)
	if err != nil {
		t.Fatalf("Не удалось создать S-box: %v", err)
	}

	for i := 0; i < 256; i++ {
		input := byte(i)
		inverse := sbox.inverse[input]
		forward := sbox.forward[inverse]

		if forward != input {
			t.Errorf("Обратная S-box не взаимно обратна для 0x%02X: inverse=0x%02X, forward=0x%02X",
				input, inverse, forward)
		}
	}
}

// Тест SubBytes
func TestSubBytes(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	state := []byte{0x00, 0x01, 0x02, 0x53, 0xCA, 0xFF}
	expected := make([]byte, len(state))

	// Вычисляем ожидаемый результат
	for i, b := range state {
		expected[i] = sbox.forward[b]
	}

	sbox.SubBytes(state)

	for i := range state {
		if state[i] != expected[i] {
			t.Errorf("SubBytes[%d]: получено 0x%02X, ожидалось 0x%02X",
				i, state[i], expected[i])
		}
	}
}

// Тест InvSubBytes
func TestInvSubBytes(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	state := []byte{0x00, 0x01, 0x02, 0x53, 0xCA, 0xFF}
	expected := make([]byte, len(state))

	// Вычисляем ожидаемый результат
	for i, b := range state {
		expected[i] = sbox.inverse[b]
	}

	sbox.InvSubBytes(state)

	for i := range state {
		if state[i] != expected[i] {
			t.Errorf("InvSubBytes[%d]: получено 0x%02X, ожидалось 0x%02X",
				i, state[i], expected[i])
		}
	}
}

// Тест что SubBytes и InvSubBytes взаимно обратны
func TestSubBytes_InvSubBytes(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	original := []byte{0x00, 0x01, 0x02, 0x53, 0xCA, 0xFF, 0x10, 0x20, 0x30, 0x40}
	state := make([]byte, len(original))
	copy(state, original)

	sbox.SubBytes(state)
	sbox.InvSubBytes(state)

	for i := range state {
		if state[i] != original[i] {
			t.Errorf("SubBytes -> InvSubBytes не восстановил исходное значение[%d]: получено 0x%02X, ожидалось 0x%02X",
				i, state[i], original[i])
		}
	}
}

// Тест что разные модули дают разные S-box
func TestSBox_DifferentModuli(t *testing.T) {
	sbox1, _ := NewSBox(0x1B)
	sbox2, _ := NewSBox(0x1D)

	// Должны быть различия в таблицах подстановки
	differences := 0
	for i := 0; i < 256; i++ {
		if sbox1.forward[i] != sbox2.forward[i] {
			differences++
		}
	}

	if differences == 0 {
		t.Error("S-box для разных модулей должны различаться")
	}

	// Должно быть значительное количество различий (> 50%)
	if differences < 128 {
		t.Errorf("Слишком мало различий между S-box для разных модулей: %d из 256", differences)
	}
}

// Тест что S-box для 0 возвращает константу
func TestSBox_Zero(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	// S-box для 0 всегда должна быть одна и та же (после аффинного преобразования)
	// Для стандартного AES это 0x63
	result := sbox.forward[0]

	if result != 0x63 {
		t.Errorf("S-box[0] = 0x%02X; для стандартного AES модуля ожидалось 0x63", result)
	}
}

// Тест GetForward
func TestGetForward(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	forward := sbox.GetForward()

	// Проверяем что возвращается правильная таблица
	for i := 0; i < 256; i++ {
		if forward[i] != sbox.forward[i] {
			t.Errorf("GetForward()[%d] != sbox.forward[%d]", i, i)
		}
	}
}

// Тест GetInverse
func TestGetInverse(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	inverse := sbox.GetInverse()

	// Проверяем что возвращается правильная таблица
	for i := 0; i < 256; i++ {
		if inverse[i] != sbox.inverse[i] {
			t.Errorf("GetInverse()[%d] != sbox.inverse[%d]", i, i)
		}
	}
}

// Тест getBit
func TestGetBit(t *testing.T) {
	tests := []struct {
		b        byte
		pos      int
		expected byte
	}{
		{0x00, 0, 0},
		{0x01, 0, 1},
		{0x01, 1, 0},
		{0x02, 1, 1},
		{0xFF, 7, 1},
		{0x80, 7, 1},
		{0x80, 0, 0},
		{0x53, 0, 1}, // 01010011
		{0x53, 1, 1},
		{0x53, 4, 1},
		{0x53, 6, 1},
	}

	for _, tt := range tests {
		result := getBit(tt.b, tt.pos)
		if result != tt.expected {
			t.Errorf("getBit(0x%02X, %d) = %d; ожидалось %d",
				tt.b, tt.pos, result, tt.expected)
		}
	}
}

// Тест что все значения в S-box уникальны (биекция)
func TestSBox_Bijection(t *testing.T) {
	sbox, _ := NewSBox(0x1B)

	// Проверяем прямую S-box
	seen := make(map[byte]bool)
	for i := 0; i < 256; i++ {
		val := sbox.forward[i]
		if seen[val] {
			t.Errorf("Дубликат значения 0x%02X в прямой S-box", val)
		}
		seen[val] = true
	}

	// Проверяем обратную S-box
	seen = make(map[byte]bool)
	for i := 0; i < 256; i++ {
		val := sbox.inverse[i]
		if seen[val] {
			t.Errorf("Дубликат значения 0x%02X в обратной S-box", val)
		}
		seen[val] = true
	}
}

// Бенчмарк для создания S-box
func BenchmarkNewSBox(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewSBox(0x1B)
	}
}

// Бенчмарк для SubBytes
func BenchmarkSubBytes(b *testing.B) {
	sbox, _ := NewSBox(0x1B)
	state := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sbox.SubBytes(state)
	}
}

// Бенчмарк для InvSubBytes
func BenchmarkInvSubBytes(b *testing.B) {
	sbox, _ := NewSBox(0x1B)
	state := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sbox.InvSubBytes(state)
	}
}
