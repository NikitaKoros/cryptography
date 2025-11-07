package core

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
)

// CipherMode перечисление режимов шифрования
type CipherMode int

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

// PaddingMode перечисление режимов паддинга
type PaddingMode int

const (
	PadZeros PaddingMode = iota
	PadANSIX923
	PadPKCS7
	PadISO10126
)

// CipherContext — контекст симметричного шифрования
type CipherContext struct {
	cipher      SymmetricCipher
	mode        CipherMode
	padding     PaddingMode
	blockSize   int
	iv          []byte // optional
	modeOptions []interface{}
}

// NewCipherContext создаёт контекст. iv может быть nil для режимов ECB.
func NewCipherContext(c SymmetricCipher, mode CipherMode, padding PaddingMode, iv []byte, opts ...interface{}) *CipherContext {
	return &CipherContext{
		cipher:      c,
		mode:        mode,
		padding:     padding,
		blockSize:   8, // для DES
		iv:          iv,
		modeOptions: opts,
	}
}

// --- Padding helpers ---
func applyPadding(data []byte, blockSize int, mode PaddingMode) ([]byte, error) {
	switch mode {
	case PadZeros:
		pad := (blockSize - (len(data) % blockSize)) % blockSize
		if pad == 0 {
			return data, nil
		}
		return append(data, bytes.Repeat([]byte{0x00}, pad)...), nil
	case PadPKCS7:
		pad := blockSize - (len(data) % blockSize)
		if pad == 0 {
			pad = blockSize
		}
		return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...), nil
	case PadANSIX923:
		pad := blockSize - (len(data) % blockSize)
		if pad == 0 {
			pad = blockSize
		}
		out := append(data, bytes.Repeat([]byte{0x00}, pad-1)...)
		out = append(out, byte(pad))
		return out, nil
	case PadISO10126:
		pad := blockSize - (len(data) % blockSize)
		if pad == 0 {
			pad = blockSize
		}
		random := make([]byte, pad-1)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		out := append(data, random...)
		out = append(out, byte(pad))
		return out, nil
	default:
		return nil, errors.New("unknown padding")
	}
}

func removePadding(data []byte, blockSize int, mode PaddingMode) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	switch mode {
	case PadZeros:
		for len(data) > 0 && data[len(data)-1] == 0x00 {
			data = data[:len(data)-1]
		}
		return data, nil
	case PadPKCS7, PadANSIX923, PadISO10126:
		pad := int(data[len(data)-1])
		if pad <= 0 || pad > blockSize {
			return nil, errors.New("invalid padding")
		}
		return data[:len(data)-pad], nil
	default:
		return nil, errors.New("unknown padding")
	}
}

// xorBytes helper
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// --- High-level Encrypt/Decrypt ---

func (ctx *CipherContext) Encrypt(plaintext []byte) ([]byte, error) {
	if ctx.cipher == nil {
		return nil, errors.New("cipher not set")
	}
	padded, err := applyPadding(plaintext, ctx.blockSize, ctx.padding)
	if err != nil {
		return nil, err
	}

	switch ctx.mode {
	case ECB:
		return ctx.encryptECB(padded)
	case CBC:
		return ctx.encryptCBC(padded)
	case PCBC:
		return ctx.encryptPCBC(padded)
	case CFB:
		return ctx.encryptCFB(padded)
	case OFB:
		return ctx.encryptOFB(padded)
	case CTR:
		return ctx.encryptCTR(padded)
	case RandomDelta:
		return ctx.encryptRandomDelta(padded)
	default:
		return nil, errors.New("unsupported mode")
	}
}

func (ctx *CipherContext) Decrypt(ciphertext []byte) ([]byte, error) {
	if ctx.cipher == nil {
		return nil, errors.New("cipher not set")
	}
	if len(ciphertext)%ctx.blockSize != 0 {
		return nil, errors.New("ciphertext not multiple of block size")
	}

	var plain []byte
	var err error

	switch ctx.mode {
	case ECB:
		plain, err = ctx.decryptECB(ciphertext)
	case CBC:
		plain, err = ctx.decryptCBC(ciphertext)
	case PCBC:
		plain, err = ctx.decryptPCBC(ciphertext)
	case CFB:
		plain, err = ctx.decryptCFB(ciphertext)
	case OFB:
		plain, err = ctx.decryptOFB(ciphertext)
	case CTR:
		plain, err = ctx.decryptCTR(ciphertext)
	case RandomDelta:
		plain, err = ctx.decryptRandomDelta(ciphertext)
	default:
		return nil, errors.New("unsupported mode")
	}

	if err != nil {
		return nil, err
	}
	return removePadding(plain, ctx.blockSize, ctx.padding)
}

// --- Асинхронные версии ---
func (ctx *CipherContext) EncryptAsync(plaintext []byte) (<-chan []byte, <-chan error) {
	outCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := ctx.Encrypt(plaintext)
		if err != nil {
			errCh <- err
		} else {
			outCh <- res
		}
		close(outCh)
		close(errCh)
	}()
	return outCh, errCh
}

func (ctx *CipherContext) DecryptAsync(ciphertext []byte) (<-chan []byte, <-chan error) {
	outCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := ctx.Decrypt(ciphertext)
		if err != nil {
			errCh <- err
		} else {
			outCh <- res
		}
		close(outCh)
		close(errCh)
	}()
	return outCh, errCh
}

// --- Режимы ---

// ECB (параллельно)
func (ctx *CipherContext) encryptECB(padded []byte) ([]byte, error) {
	n := len(padded) / ctx.blockSize
	out := make([]byte, len(padded))
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			block := padded[i*ctx.blockSize : (i+1)*ctx.blockSize]
			res, err := ctx.cipher.EncryptBlock(block)
			if err == nil {
				copy(out[i*ctx.blockSize:], res)
			}
		}()
	}
	wg.Wait()
	return out, nil
}

func (ctx *CipherContext) decryptECB(ciphertext []byte) ([]byte, error) {
	n := len(ciphertext) / ctx.blockSize
	out := make([]byte, len(ciphertext))
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			block := ciphertext[i*ctx.blockSize : (i+1)*ctx.blockSize]
			res, err := ctx.cipher.DecryptBlock(block)
			if err == nil {
				copy(out[i*ctx.blockSize:], res)
			}
		}()
	}
	wg.Wait()
	return out, nil
}

// CBC
func (ctx *CipherContext) encryptCBC(padded []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("CBC requires IV of block size")
	}
	out := make([]byte, len(padded))
	prev := make([]byte, ctx.blockSize)
	copy(prev, ctx.iv)

	for i := 0; i < len(padded); i += ctx.blockSize {
		block := xorBytes(padded[i:i+ctx.blockSize], prev)
		c, err := ctx.cipher.EncryptBlock(block)
		if err != nil {
			return nil, err
		}
		copy(out[i:], c)
		copy(prev, c)
	}
	return out, nil
}

func (ctx *CipherContext) decryptCBC(ciphertext []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("CBC requires IV of block size")
	}
	out := make([]byte, len(ciphertext))
	prev := make([]byte, ctx.blockSize)
	copy(prev, ctx.iv)

	for i := 0; i < len(ciphertext); i += ctx.blockSize {
		block := ciphertext[i : i+ctx.blockSize]
		d, err := ctx.cipher.DecryptBlock(block)
		if err != nil {
			return nil, err
		}
		plain := xorBytes(d, prev)
		copy(out[i:], plain)
		copy(prev, block)
	}
	return out, nil
}

// CFB
func (ctx *CipherContext) encryptCFB(padded []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("CFB requires IV of block size")
	}
	out := make([]byte, len(padded))
	feedback := append([]byte{}, ctx.iv...)

	for i := 0; i < len(padded); i += ctx.blockSize {
		stream, err := ctx.cipher.EncryptBlock(feedback)
		if err != nil {
			return nil, err
		}
		block := padded[i : i+ctx.blockSize]
		c := xorBytes(block, stream)
		copy(out[i:], c)
		feedback = c
	}
	return out, nil
}

func (ctx *CipherContext) decryptCFB(ciphertext []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("CFB requires IV of block size")
	}
	out := make([]byte, len(ciphertext))
	feedback := append([]byte{}, ctx.iv...)

	for i := 0; i < len(ciphertext); i += ctx.blockSize {
		stream, err := ctx.cipher.EncryptBlock(feedback)
		if err != nil {
			return nil, err
		}
		block := ciphertext[i : i+ctx.blockSize]
		plain := xorBytes(block, stream)
		copy(out[i:], plain)
		feedback = block
	}
	return out, nil
}

// OFB
func (ctx *CipherContext) encryptOFB(padded []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("OFB requires IV of block size")
	}
	out := make([]byte, len(padded))
	feedback := append([]byte{}, ctx.iv...)

	for i := 0; i < len(padded); i += ctx.blockSize {
		var err error
		feedback, err = ctx.cipher.EncryptBlock(feedback)
		if err != nil {
			return nil, err
		}
		block := padded[i : i+ctx.blockSize]
		c := xorBytes(block, feedback)
		copy(out[i:], c)
	}
	return out, nil
}

func (ctx *CipherContext) decryptOFB(ciphertext []byte) ([]byte, error) {
	return ctx.encryptOFB(ciphertext)
}

// CTR
func (ctx *CipherContext) encryptCTR(padded []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("CTR requires nonce/IV of block size")
	}
	n := len(padded) / ctx.blockSize
	out := make([]byte, len(padded))
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			// Каждый блок имеет свой собственный счетчик
			counter := make([]byte, ctx.blockSize)
			copy(counter, ctx.iv)
			addUint64ToBE(counter, uint64(i))
			
			keystream, err := ctx.cipher.EncryptBlock(counter)
			if err == nil {
				block := padded[i*ctx.blockSize : (i+1)*ctx.blockSize]
				res := xorBytes(block, keystream)
				copy(out[i*ctx.blockSize:], res)
			}
		}(i)
	}
	wg.Wait()
	return out, nil
}

func (ctx *CipherContext) decryptCTR(ciphertext []byte) ([]byte, error) {
	return ctx.encryptCTR(ciphertext)
}

// --- Utils ---
func addUint64ToBE(buf []byte, v uint64) {
	if len(buf) < 8 {
		var carry uint64 = v
		for i := len(buf) - 1; i >= 0 && carry > 0; i-- {
			sum := uint64(buf[i]) + (carry & 0xFF)
			buf[i] = byte(sum & 0xFF)
			carry = sum >> 8
		}
		return
	}
	last := buf[len(buf)-8:]
	cur := binary.BigEndian.Uint64(last)
	binary.BigEndian.PutUint64(last, cur+v)
}

// MaxInMemorySize максимальный размер файла для загрузки в память (10 МБ)
const MaxInMemorySize = 10 * 1024 * 1024

// --- Файловые операции ---
func (ctx *CipherContext) EncryptFile(inPath, outPath string) error {
	info, err := os.Stat(inPath)
	if err != nil {
		return err
	}

	// Для больших файлов используем потоковое шифрование
	if info.Size() > MaxInMemorySize {
		inFile, err := os.Open(inPath)
		if err != nil {
			return err
		}
		defer inFile.Close()

		outFile, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		// Читаем и шифруем порциями
		buffer := make([]byte, 1024*1024) // 1MB буфер
		for {
			n, readErr := inFile.Read(buffer)
			if n > 0 {
				encrypted, encErr := ctx.Encrypt(buffer[:n])
				if encErr != nil {
					return encErr
				}
				if _, writeErr := outFile.Write(encrypted); writeErr != nil {
					return writeErr
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	}

	// Для маленьких файлов загружаем в память
	in, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	out, err := ctx.Encrypt(in)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, out, 0644)
}

func (ctx *CipherContext) DecryptFile(inPath, outPath string) error {
	info, err := os.Stat(inPath)
	if err != nil {
		return err
	}

	// Для больших файлов используем потоковое дешифрование
	if info.Size() > MaxInMemorySize {
		inFile, err := os.Open(inPath)
		if err != nil {
			return err
		}
		defer inFile.Close()

		outFile, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		// Читаем и дешифруем порциями
		buffer := make([]byte, 1024*1024+ctx.blockSize) // 1MB + размер блока
		for {
			n, readErr := inFile.Read(buffer)
			if n > 0 {
				decrypted, decErr := ctx.Decrypt(buffer[:n])
				if decErr != nil {
					return decErr
				}
				if _, writeErr := outFile.Write(decrypted); writeErr != nil {
					return writeErr
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	}

	// Для маленьких файлов загружаем в память
	in, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	out, err := ctx.Decrypt(in)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, out, 0644)
}

// EncryptStream шифрует данные из reader в writer блоками
func (ctx *CipherContext) EncryptStream(r io.Reader, w io.Writer) error {
	buffer := make([]byte, 4096) // Буфер 4KB
	remainder := []byte{}

	for {
		n, err := r.Read(buffer)
		if n > 0 {
			// Добавляем прочитанные данные к остатку
			data := append(remainder, buffer[:n]...)

			// Шифруем полные блоки
			fullBlocks := (len(data) / ctx.blockSize) * ctx.blockSize
			if fullBlocks > 0 {
				encrypted, encErr := ctx.Encrypt(data[:fullBlocks])
				if encErr != nil {
					return encErr
				}
				if _, wErr := w.Write(encrypted); wErr != nil {
					return wErr
				}
			}

			// Сохраняем неполный блок
			remainder = data[fullBlocks:]
		}

		if err == io.EOF {
			// Шифруем последний блок с паддингом
			if len(remainder) > 0 || ctx.padding != PadZeros {
				encrypted, encErr := ctx.Encrypt(remainder)
				if encErr != nil {
					return encErr
				}
				if _, wErr := w.Write(encrypted); wErr != nil {
					return wErr
				}
			}
			break
		}

		if err != nil {
			return err
		}
	}
	return nil
}

// DecryptStream дешифрует данные из reader в writer
// Примечание: для правильного удаления паддинга нужно читать весь ciphertext
func (ctx *CipherContext) DecryptStream(r io.Reader, w io.Writer) error {
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(r); err != nil {
		return err
	}
	out, err := ctx.Decrypt(buf.Bytes())
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// PCBC: Propagating Cipher Block Chaining
func (ctx *CipherContext) encryptPCBC(padded []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("PCBC requires IV of block size")
	}
	out := make([]byte, len(padded))
	prevPlain := make([]byte, ctx.blockSize)
	prevCipher := make([]byte, ctx.blockSize)
	copy(prevCipher, ctx.iv)

	for i := 0; i < len(padded); i += ctx.blockSize {
		block := padded[i : i+ctx.blockSize]

		// X = block XOR (prevPlain XOR prevCipher)
		x := xorBytes(block, xorBytes(prevPlain, prevCipher))
		c, err := ctx.cipher.EncryptBlock(x)
		if err != nil {
			return nil, err
		}
		copy(out[i:], c)

		copy(prevPlain, block)
		copy(prevCipher, c)
	}
	return out, nil
}

func (ctx *CipherContext) decryptPCBC(ciphertext []byte) ([]byte, error) {
	if ctx.iv == nil || len(ctx.iv) != ctx.blockSize {
		return nil, errors.New("PCBC requires IV of block size")
	}
	out := make([]byte, len(ciphertext))
	prevPlain := make([]byte, ctx.blockSize)
	prevCipher := make([]byte, ctx.blockSize)
	copy(prevCipher, ctx.iv)

	for i := 0; i < len(ciphertext); i += ctx.blockSize {
		block := ciphertext[i : i+ctx.blockSize]
		d, err := ctx.cipher.DecryptBlock(block)
		if err != nil {
			return nil, err
		}

		// plaintext = d XOR (prevPlain XOR prevCipher)
		plain := xorBytes(d, xorBytes(prevPlain, prevCipher))
		copy(out[i:], plain)

		copy(prevPlain, plain)
		copy(prevCipher, block)
	}
	return out, nil
}

// RandomDelta режим: добавляем случайную "дельту" перед каждым блоком
// Начальная delta добавляется в начало ciphertext для дешифрования
func (ctx *CipherContext) encryptRandomDelta(padded []byte) ([]byte, error) {
	delta := make([]byte, ctx.blockSize)
	if _, err := rand.Read(delta); err != nil {
		return nil, err
	}
	
	// Добавляем начальную delta в начало результата
	out := make([]byte, ctx.blockSize+len(padded))
	copy(out[:ctx.blockSize], delta)
	
	for i := 0; i < len(padded); i += ctx.blockSize {
		block := xorBytes(padded[i:i+ctx.blockSize], delta)
		c, err := ctx.cipher.EncryptBlock(block)
		if err != nil {
			return nil, err
		}
		copy(out[ctx.blockSize+i:], c)

		// обновляем delta (например, как XOR с ciphertext)
		delta = xorBytes(delta, c)
	}
	return out, nil
}

func (ctx *CipherContext) decryptRandomDelta(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < ctx.blockSize {
		return nil, errors.New("ciphertext too short for RandomDelta")
	}
	
	// Извлекаем начальную delta из начала ciphertext
	delta := make([]byte, ctx.blockSize)
	copy(delta, ciphertext[:ctx.blockSize])
	
	actualCiphertext := ciphertext[ctx.blockSize:]
	out := make([]byte, len(actualCiphertext))
	
	for i := 0; i < len(actualCiphertext); i += ctx.blockSize {
		block := actualCiphertext[i : i+ctx.blockSize]
		d, err := ctx.cipher.DecryptBlock(block)
		if err != nil {
			return nil, err
		}
		plain := xorBytes(d, delta)
		copy(out[i:], plain)

		delta = xorBytes(delta, block)
	}
	return out, nil
}

// String методы для удобного вывода
func (m CipherMode) String() string {
	switch m {
	case ECB:
		return "ECB"
	case CBC:
		return "CBC"
	case PCBC:
		return "PCBC"
	case CFB:
		return "CFB"
	case OFB:
		return "OFB"
	case CTR:
		return "CTR"
	case RandomDelta:
		return "RandomDelta"
	default:
		return "Unknown"
	}
}

func (p PaddingMode) String() string {
	switch p {
	case PadZeros:
		return "PadZeros"
	case PadPKCS7:
		return "PadPKCS7"
	case PadANSIX923:
		return "PadANSIX923"
	case PadISO10126:
		return "PadISO10126"
	default:
		return "Unknown"
	}
}
