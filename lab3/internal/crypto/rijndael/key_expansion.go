package rijndael

// expandKey выполняет расширение ключа для получения раундовых ключей
func (r *Rijndael) expandKey(key []byte) ([][]byte, error) {
	// Количество 32-битных слов, необходимых для всех раундовых ключей
	totalWords := r.Nb * (r.Nr + 1)

	// Массив слов для хранения расширенного ключа
	w := make([][]byte, totalWords)
	for i := range w {
		w[i] = make([]byte, 4)
	}

	// Копируем исходный ключ в первые Nk слов
	for i := 0; i < r.Nk; i++ {
		w[i][0] = key[4*i]
		w[i][1] = key[4*i+1]
		w[i][2] = key[4*i+2]
		w[i][3] = key[4*i+3]
	}

	// Расширяем ключ
	for i := r.Nk; i < totalWords; i++ {
		temp := make([]byte, 4)
		copy(temp, w[i-1])

		if i%r.Nk == 0 {
			// Применяем RotWord, SubWord и XOR с Rcon
			temp = r.rotWord(temp)
			temp = r.subWord(temp)
			temp = r.xorWord(temp, r.rcon(i/r.Nk))
		} else if r.Nk > 6 && i%r.Nk == 4 {
			// Для 256-битных ключей применяем дополнительный SubWord
			temp = r.subWord(temp)
		}

		// w[i] = w[i-Nk] XOR temp
		w[i] = r.xorWord(w[i-r.Nk], temp)
	}

	// Формируем раундовые ключи из слов
	roundKeys := make([][]byte, r.Nr+1)
	for round := 0; round <= r.Nr; round++ {
		roundKeys[round] = make([]byte, r.blockSize)
		for col := 0; col < r.Nb; col++ {
			wordIndex := round*r.Nb + col
			for row := 0; row < 4; row++ {
				roundKeys[round][row+4*col] = w[wordIndex][row]
			}
		}
	}

	return roundKeys, nil
}

// rotWord выполняет циклический сдвиг байтов в слове влево на 1 позицию
func (r *Rijndael) rotWord(word []byte) []byte {
	return []byte{word[1], word[2], word[3], word[0]}
}

// subWord применяет S-box к каждому байту в слове
func (r *Rijndael) subWord(word []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = r.sbox.forward[word[i]]
	}
	return result
}

// xorWord выполняет XOR двух слов
func (r *Rijndael) xorWord(a, b []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// rcon возвращает константу раунда для расширения ключа
func (r *Rijndael) rcon(round int) []byte {
	// Rcon[i] = [RC[i], 0, 0, 0], где RC[i] = x^(i-1) в GF(2^8)
	rc := byte(1)
	for i := 1; i < round; i++ {
		rc = r.gf.XTime(rc)
	}
	return []byte{rc, 0, 0, 0}
}
