package frog

import (
	"errors"
)

const (
	// BlockSize размер блока FROG в байтах (128 бит)
	BlockSize = 16
	// NumIter количество итераций шифрования
	NumIter = 8
)

// randomSeed - значения из RAND Corporation's "A Million Random Digits"
var randomSeed = []byte{
	113, 21, 232, 18, 113, 92, 63, 157, 124, 193, 166, 197, 126, 56, 229, 229,
	156, 162, 54, 17, 230, 89, 189, 87, 169, 0, 81, 204, 8, 70, 203, 225,
	160, 59, 167, 189, 100, 157, 84, 11, 7, 130, 29, 51, 32, 45, 135, 237,
	139, 33, 17, 221, 24, 50, 89, 74, 21, 205, 191, 242, 84, 53, 3, 230,
	231, 118, 15, 15, 107, 4, 21, 34, 3, 156, 57, 66, 93, 255, 191, 3,
	85, 135, 205, 200, 185, 204, 52, 37, 35, 24, 68, 185, 201, 10, 224, 234,
	7, 120, 201, 115, 216, 103, 57, 255, 93, 110, 42, 249, 68, 14, 29, 55,
	128, 84, 37, 152, 221, 137, 39, 11, 252, 50, 144, 35, 178, 190, 43, 162,
	103, 249, 109, 8, 235, 33, 158, 111, 252, 205, 169, 54, 10, 20, 221, 201,
	178, 224, 89, 184, 182, 65, 201, 10, 60, 6, 191, 174, 79, 98, 26, 160,
	252, 51, 63, 79, 6, 102, 123, 173, 49, 3, 110, 233, 90, 158, 228, 210,
	209, 237, 30, 95, 28, 179, 204, 220, 72, 163, 77, 166, 192, 98, 165, 25,
	145, 162, 91, 212, 41, 230, 110, 6, 107, 187, 127, 38, 82, 98, 30, 67,
	225, 80, 208, 134, 60, 250, 153, 87, 148, 60, 66, 165, 72, 29, 165, 82,
	211, 207, 0, 177, 206, 13, 6, 14, 92, 248, 60, 201, 132, 95, 35, 215,
	118, 177, 121, 180, 27, 83, 131, 26, 39, 46, 12,
}

// IterKey представляет один итерационный ключ
type IterKey struct {
	XorBuf      [BlockSize]byte
	SubstPermu  [256]byte
	BombPermu   [BlockSize]byte
}

// InternalKey представляет внутренний ключ FROG
type InternalKey struct {
	KeyE [NumIter]IterKey // ключи для шифрования
	KeyD [NumIter]IterKey // ключи для дешифрования
}

// FROG представляет шифр FROG
type FROG struct {
	key *InternalKey
}

// New создает новый экземпляр FROG с заданным ключом
func New(key []byte) (*FROG, error) {
	if len(key) == 0 {
		return nil, errors.New("ключ не может быть пустым")
	}

	frog := &FROG{}
	err := frog.SetEncryptionKey(key)
	if err != nil {
		return nil, err
	}

	return frog, nil
}

// SetEncryptionKey устанавливает ключ для шифрования
func (f *FROG) SetEncryptionKey(key []byte) error {
	internalKey, err := hashKey(key)
	if err != nil {
		return err
	}
	f.key = internalKey
	return nil
}

// SetDecryptionKey устанавливает ключ для дешифрования (для FROG это то же самое)
func (f *FROG) SetDecryptionKey(key []byte) error {
	return f.SetEncryptionKey(key)
}

// BlockSize возвращает размер блока шифра
func (f *FROG) BlockSize() int {
	return BlockSize
}

// EncryptBlock шифрует один блок данных
func (f *FROG) EncryptBlock(plaintext []byte) ([]byte, error) {
	if len(plaintext) != BlockSize {
		return nil, errors.New("размер блока должен быть 16 байт")
	}

	if f.key == nil {
		return nil, errors.New("ключ не установлен")
	}

	block := make([]byte, BlockSize)
	copy(block, plaintext)

	return encryptFrog(block, f.key.KeyE[:]), nil
}

// DecryptBlock дешифрует один блок данных
func (f *FROG) DecryptBlock(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != BlockSize {
		return nil, errors.New("размер блока должен быть 16 байт")
	}

	if f.key == nil {
		return nil, errors.New("ключ не установлен")
	}

	block := make([]byte, BlockSize)
	copy(block, ciphertext)

	return decryptFrog(block, f.key.KeyD[:]), nil
}

// encryptFrog выполняет шифрование блока FROG
func encryptFrog(plainText []byte, key []IterKey) []byte {
	for ite := 0; ite < NumIter; ite++ {
		for ib := 0; ib < BlockSize; ib++ {
			plainText[ib] ^= key[ite].XorBuf[ib]
			plainText[ib] = key[ite].SubstPermu[plainText[ib]]

			if ib < BlockSize-1 {
				plainText[ib+1] ^= plainText[ib]
			} else {
				plainText[0] ^= plainText[BlockSize-1]
			}

			plainText[key[ite].BombPermu[ib]] ^= plainText[ib]
		}
	}
	return plainText
}

// decryptFrog выполняет дешифрование блока FROG
func decryptFrog(cipherText []byte, key []IterKey) []byte {
	for ite := NumIter - 1; ite >= 0; ite-- {
		for ib := BlockSize - 1; ib >= 0; ib-- {
			cipherText[key[ite].BombPermu[ib]] ^= cipherText[ib]

			if ib < BlockSize-1 {
				cipherText[ib+1] ^= cipherText[ib]
			} else {
				cipherText[0] ^= cipherText[BlockSize-1]
			}

			cipherText[ib] = key[ite].SubstPermu[cipherText[ib]]
			cipherText[ib] ^= key[ite].XorBuf[ib]
		}
	}
	return cipherText
}

// makePermutation создает перестановку из массива байтов
func makePermutation(permu []byte) []byte {
	lastElem := len(permu) - 1
	use := make([]byte, len(permu))
	for i := range use {
		use[i] = byte(i)
	}

	last := lastElem
	j := 0

	for i := 0; i < lastElem; i++ {
		j = (j + int(permu[i])) % (last + 1)
		permu[i] = use[j]

		// Удаляем использованное значение
		if j < last {
			copy(use[j:last], use[j+1:last+1])
		}
		last--
		if j > last {
			j = 0
		}
	}
	permu[lastElem] = use[0]

	return permu
}

// invertPermutation инвертирует перестановку
func invertPermutation(orig []byte) []byte {
	invert := make([]byte, len(orig))
	for i, v := range orig {
		invert[v] = byte(i)
	}
	return invert
}

// makeInternalKey обрабатывает неструктурированный внутренний ключ
func makeInternalKey(decrypting bool, keyOri []IterKey) []IterKey {
	key := make([]IterKey, NumIter)
	for i := 0; i < NumIter; i++ {
		key[i] = keyOri[i]
	}

	for ite := 0; ite < NumIter; ite++ {
		// Создаем перестановку подстановки
		substPermu := make([]byte, 256)
		copy(substPermu, key[ite].SubstPermu[:])
		substPermu = makePermutation(substPermu)

		if decrypting {
			substPermu = invertPermutation(substPermu)
		}
		copy(key[ite].SubstPermu[:], substPermu)

		// Создаем перестановку bomb
		bombPermu := make([]byte, BlockSize)
		copy(bombPermu, key[ite].BombPermu[:])
		bombPermu = makePermutation(bombPermu)
		copy(key[ite].BombPermu[:], bombPermu)

		// Объединяем меньшие циклы в один
		used := make([]byte, BlockSize)
		j := 0
		for i := 0; i < BlockSize-1; i++ {
			if key[ite].BombPermu[j] == 0 {
				k := j
				for {
					k = (k + 1) % BlockSize
					if used[k] == 0 {
						break
					}
				}
				key[ite].BombPermu[j] = byte(k)
				l := k
				for key[ite].BombPermu[l] != byte(k) {
					l = int(key[ite].BombPermu[l])
				}
				key[ite].BombPermu[l] = 0
			}
			used[j] = 1
			j = int(key[ite].BombPermu[j])
		}

		// Удаляем ссылки на следующий элемент
		for i := 0; i < BlockSize; i++ {
			j := i + 1
			if i == BlockSize-1 {
				j = 0
			}
			if key[ite].BombPermu[i] == byte(j) {
				k := j + 1
				if j == BlockSize-1 {
					k = 0
				}
				key[ite].BombPermu[i] = byte(k)
			}
		}
	}

	return key
}

// hashKey хеширует бинарный ключ во внутренний ключ
func hashKey(binaryKey []byte) (*InternalKey, error) {
	keyLen := len(binaryKey)

	// Инициализируем simpleKey
	simpleKey := make([]IterKey, NumIter)

	sizeKey := (BlockSize + 256 + BlockSize) * NumIter
	iSeed := 0
	iFrase := 0

	for i := 0; i < sizeKey; i++ {
		iterIdx := i / (BlockSize + 256 + BlockSize)
		offset := i % (BlockSize + 256 + BlockSize)

		value := randomSeed[iSeed] ^ binaryKey[iFrase]

		if offset < BlockSize {
			simpleKey[iterIdx].XorBuf[offset] = value
		} else if offset < BlockSize+256 {
			simpleKey[iterIdx].SubstPermu[offset-BlockSize] = value
		} else {
			simpleKey[iterIdx].BombPermu[offset-BlockSize-256] = value
		}

		if iSeed < 250 {
			iSeed++
		} else {
			iSeed = 0
		}

		if iFrase < keyLen-1 {
			iFrase++
		} else {
			iFrase = 0
		}
	}

	// Преобразуем simpleKey в валидный внутренний ключ
	simpleKey = makeInternalKey(false, simpleKey)

	// Инициализируем IV вектор
	buffer := make([]byte, BlockSize)
	last := keyLen - 1
	if last > BlockSize-1 {
		last = BlockSize - 1
	}
	for i := 0; i <= last; i++ {
		buffer[i] ^= binaryKey[i]
	}
	buffer[0] ^= byte(keyLen)

	// Заполняем randomKey шифротекстами
	internalKey := make([]IterKey, NumIter)
	posi := 0

	for posi != sizeKey {
		buffer = encryptFrog(buffer, simpleKey)
		size := sizeKey - posi
		if size > BlockSize {
			size = BlockSize
		}

		for i := 0; i < size; i++ {
			iterIdx := (posi + i) / (BlockSize + 256 + BlockSize)
			offset := (posi + i) % (BlockSize + 256 + BlockSize)

			if offset < BlockSize {
				internalKey[iterIdx].XorBuf[offset] = buffer[i]
			} else if offset < BlockSize+256 {
				internalKey[iterIdx].SubstPermu[offset-BlockSize] = buffer[i]
			} else {
				internalKey[iterIdx].BombPermu[offset-BlockSize-256] = buffer[i]
			}
		}

		posi += size
	}

	// Создаем ключи для шифрования и дешифрования
	result := &InternalKey{}
	keyE := makeInternalKey(false, internalKey)
	keyD := makeInternalKey(true, internalKey)

	copy(result.KeyE[:], keyE)
	copy(result.KeyD[:], keyD)

	return result, nil
}
