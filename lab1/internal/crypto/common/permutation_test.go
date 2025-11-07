package common

import (
	"bytes"
	"testing"
)

func TestBytesToBits(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		bitOrder BitOrder
		expected []bool
	}{
		{
			name:     "Single byte MSBToLSB",
			data:     []byte{0b10110001},
			bitOrder: MSBToLSB,
			expected: []bool{true, false, true, true, false, false, false, true},
		},
		{
			name:     "Single byte LSBToMSB",
			data:     []byte{0b10110001},
			bitOrder: LSBToMSB,
			expected: []bool{true, false, false, false, true, true, false, true},
		},
		{
			name:     "Two bytes MSBToLSB",
			data:     []byte{0xFF, 0x00},
			bitOrder: MSBToLSB,
			expected: []bool{true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, false},
		},
		{
			name:     "Empty byte slice",
			data:     []byte{},
			bitOrder: MSBToLSB,
			expected: []bool{},
		},
		{
			name:     "Zero byte",
			data:     []byte{0x00},
			bitOrder: MSBToLSB,
			expected: []bool{false, false, false, false, false, false, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesToBits(tt.data, tt.bitOrder)
			if len(result) != len(tt.expected) {
				t.Fatalf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("Bit %d: got %v, want %v", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestBitsToBytes(t *testing.T) {
	tests := []struct {
		name     string
		bits     []bool
		bitOrder BitOrder
		expected []byte
	}{
		{
			name:     "8 bits MSBToLSB",
			bits:     []bool{true, false, true, true, false, false, false, true},
			bitOrder: MSBToLSB,
			expected: []byte{0b10110001},
		},
		{
			name:     "8 bits LSBToMSB",
			bits:     []bool{true, false, false, false, true, true, false, true},
			bitOrder: LSBToMSB,
			expected: []byte{0b10110001},
		},
		{
			name:     "Non-multiple of 8 bits",
			bits:     []bool{true, true, true},
			bitOrder: MSBToLSB,
			expected: []byte{0b11100000},
		},
		{
			name:     "Empty bits",
			bits:     []bool{},
			bitOrder: MSBToLSB,
			expected: []byte{},
		},
		{
			name:     "16 bits all ones",
			bits:     []bool{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true},
			bitOrder: MSBToLSB,
			expected: []byte{0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BitsToBytes(tt.bits, tt.bitOrder)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Got %08b, want %08b", result, tt.expected)
			}
		})
	}
}

func TestBytesToBitsAndBack(t *testing.T) {
	testData := [][]byte{
		{0x00},
		{0xFF},
		{0x12, 0x34, 0x56, 0x78},
		{0xAB, 0xCD, 0xEF},
	}

	for _, order := range []BitOrder{MSBToLSB, LSBToMSB} {
		for _, data := range testData {
			bits := BytesToBits(data, order)
			result := BitsToBytes(bits, order)
			if !bytes.Equal(result, data) {
				t.Errorf("Order %v: Round-trip failed for %x, got %x", order, data, result)
			}
		}
	}
}

func TestPermute(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       []int
		bitOrder   BitOrder
		startIndex StartIndex
		expected   []byte
		expectErr  bool
	}{
		{
			name:       "Simple permutation OneBased MSBToLSB",
			data:       []byte{0b10110001},
			rule:       []int{8, 7, 6, 5, 4, 3, 2, 1},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expected:   []byte{0b10001101},
		},
		{
			name:       "Simple permutation ZeroBased MSBToLSB",
			data:       []byte{0b10110001},
			rule:       []int{7, 6, 5, 4, 3, 2, 1, 0},
			bitOrder:   MSBToLSB,
			startIndex: ZeroBased,
			expected:   []byte{0b10001101},
		},
		{
			name:       "Select subset of bits",
			data:       []byte{0xFF},
			rule:       []int{1, 3, 5, 7},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expected:   []byte{0b11110000},
		},
		{
			name:       "Empty rule",
			data:       []byte{0xFF},
			rule:       []int{},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expectErr:  true,
		},
		{
			name:       "Out of range index OneBased",
			data:       []byte{0xFF},
			rule:       []int{9},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expectErr:  true,
		},
		{
			name:       "Out of range index ZeroBased",
			data:       []byte{0xFF},
			rule:       []int{8},
			bitOrder:   MSBToLSB,
			startIndex: ZeroBased,
			expectErr:  true,
		},
		{
			name:       "Negative index after adjustment",
			data:       []byte{0xFF},
			rule:       []int{0},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expectErr:  true,
		},
		{
			name:       "Multi-byte permutation",
			data:       []byte{0xAB, 0xCD},
			rule:       []int{9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expected:   []byte{0xCD, 0xAB},
		},
		{
			name:       "DES-like expansion (partial)",
			data:       []byte{0x0F},
			rule:       []int{8, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 1},
			bitOrder:   MSBToLSB,
			startIndex: OneBased,
			expected:   []byte{0b10000101, 0b11100000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Permute(tt.data, tt.rule, tt.bitOrder, tt.startIndex)
			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Got %08b, want %08b", result, tt.expected)
			}
		})
	}
}

func TestPermuteIdentity(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}
	rule := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	result, err := Permute(data, rule, MSBToLSB, OneBased)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("Identity permutation failed: got %x, want %x", result, data)
	}
}

func TestPermuteBitOrders(t *testing.T) {
	data := []byte{0b11110000}

	// MSBToLSB: биты [1,1,1,1,0,0,0,0]
	// Правило [5,6,7,8,1,2,3,4] должно дать [0,0,0,0,1,1,1,1]
	resultMSB, err := Permute(data, []int{5, 6, 7, 8, 1, 2, 3, 4}, MSBToLSB, OneBased)
	if err != nil {
		t.Fatalf("MSBToLSB error: %v", err)
	}
	if !bytes.Equal(resultMSB, []byte{0b00001111}) {
		t.Errorf("MSBToLSB: got %08b, want %08b", resultMSB, []byte{0b00001111})
	}

	// LSBToMSB: биты [0,0,0,0,1,1,1,1]
	// Правило [5,6,7,8,1,2,3,4] должно дать [1,1,1,1,0,0,0,0]
	resultLSB, err := Permute(data, []int{5, 6, 7, 8, 1, 2, 3, 4}, LSBToMSB, OneBased)
	if err != nil {
		t.Fatalf("LSBToMSB error: %v", err)
	}
	if !bytes.Equal(resultLSB, []byte{0b00001111}) {
		t.Errorf("LSBToMSB: got %08b, want %08b", resultLSB, []byte{0b00001111})
	}
}

func BenchmarkPermute(b *testing.B) {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	rule := make([]int, 64)
	for i := 0; i < 64; i++ {
		rule[i] = 64 - i
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Permute(data, rule, MSBToLSB, OneBased)
	}
}

func BenchmarkBytesToBits(b *testing.B) {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BytesToBits(data, MSBToLSB)
	}
}

func BenchmarkBitsToBytes(b *testing.B) {
	bits := make([]bool, 64)
	for i := 0; i < 64; i++ {
		bits[i] = i%2 == 0
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BitsToBytes(bits, MSBToLSB)
	}
}
