package main

import (
	"fmt"
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/attack"
	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
	"github.com/nikitakorostin/cryptography/lab2/internal/primality"
	"github.com/nikitakorostin/cryptography/lab2/internal/rsa"
)

func main() {
	fmt.Println("=== Лабораторная работа 2: Криптографические алгоритмы ===")

	// Задание 1: Number Theory Service
	demonstrateNumberTheory()

	// Задание 2: Primality Tests
	demonstratePrimalityTests()

	// Задание 3: RSA Encryption/Decryption
	demonstrateRSA()

	// Задание 4: Wiener Attack
	demonstrateWienerAttack()
}

func demonstrateNumberTheory() {
	fmt.Println("--- Задание 1: Number Theory Service ---")

	ntService := numbertheory.NewService()

	// 1. Символ Лежандра
	fmt.Println("\n1. Символ Лежандра:")
	a := big.NewInt(7)
	p := big.NewInt(13)
	legendre := ntService.LegendreSymbol(a, p)
	fmt.Printf("Legendre(%d, %d) = %d\n", a, p, legendre)

	// 2. Символ Якоби
	fmt.Println("\n2. Символ Якоби:")
	a = big.NewInt(7)
	n := big.NewInt(45)
	jacobi := ntService.JacobiSymbol(a, n)
	fmt.Printf("Jacobi(%d, %d) = %d\n", a, n, jacobi)

	// 3. НОД (алгоритм Евклида)
	fmt.Println("\n3. НОД (алгоритм Евклида):")
	a = big.NewInt(48)
	b := big.NewInt(18)
	gcd := ntService.GCD(a, b)
	fmt.Printf("GCD(%d, %d) = %d\n", a, b, gcd)

	// 4. Расширенный алгоритм Евклида (соотношение Безу)
	fmt.Println("\n4. Расширенный алгоритм Евклида:")
	a = big.NewInt(240)
	b = big.NewInt(46)
	result := ntService.ExtendedGCD(a, b)
	fmt.Printf("ExtendedGCD(%d, %d):\n", a, b)
	fmt.Printf("  GCD = %d\n", result.GCD)
	fmt.Printf("  %d * %d + %d * %d = %d\n", a, result.X, b, result.Y, result.GCD)

	// Проверка
	check := new(big.Int).Mul(a, result.X)
	temp := new(big.Int).Mul(b, result.Y)
	check.Add(check, temp)
	fmt.Printf("  Проверка: %d\n", check)

	// 5. Возведение в степень по модулю
	fmt.Println("\n5. Возведение в степень по модулю:")
	base := big.NewInt(3)
	exp := big.NewInt(7)
	mod := big.NewInt(13)
	modExp := ntService.ModExp(base, exp, mod)
	fmt.Printf("%d^%d mod %d = %d\n", base, exp, mod, modExp)

	fmt.Println()
}

func demonstratePrimalityTests() {
	fmt.Println("--- Задание 2: Primality Tests ---")

	numbers := []*big.Int{
		big.NewInt(17),   // Простое
		big.NewInt(561),  // Псевдопростое Ферма (составное)
		big.NewInt(1009), // Простое
		big.NewInt(1000), // Составное
	}

	tests := []primality.PrimalityTester{
		primality.NewFermatTest(),
		primality.NewSolovayStrassenTest(),
		primality.NewMillerRabinTest(),
	}

	minProbability := 0.99

	for _, test := range tests {
		fmt.Printf("\n%s:\n", test.GetName())
		for _, n := range numbers {
			isPrime := test.IsProbablyPrime(n, minProbability)
			fmt.Printf("  %d: %v\n", n, isPrime)
		}
	}

	fmt.Println()
}

func demonstrateRSA() {
	fmt.Println("--- Задание 3: RSA Encryption/Decryption ---")

	// Создаем RSA сервис с тестом Миллера-Рабина
	fmt.Println("\nГенерация ключей RSA (512 бит, тест Миллера-Рабина, p=0.99)...")
	rsaService := rsa.NewService(rsa.TestTypeMillerRabin, 0.99, 256)

	err := rsaService.GenerateKeys()
	if err != nil {
		fmt.Printf("Ошибка генерации ключей: %v\n", err)
		return
	}

	publicKey, _ := rsaService.GetPublicKey()
	privateKey, _ := rsaService.GetPrivateKey()

	fmt.Println("\nОткрытый ключ:")
	fmt.Printf("  N: %d бит\n", publicKey.N.BitLen())
	fmt.Printf("  E: %d\n", publicKey.E)

	fmt.Println("\nЗакрытый ключ:")
	fmt.Printf("  D: %d бит\n", privateKey.D.BitLen())
	fmt.Printf("  P: %d бит\n", privateKey.P.BitLen())
	fmt.Printf("  Q: %d бит\n", privateKey.Q.BitLen())

	// Проверка защиты от атаки Ферма
	diff := new(big.Int).Sub(privateKey.P, privateKey.Q)
	diff.Abs(diff)
	minDiff := new(big.Int).Lsh(big.NewInt(1), uint(512/4))
	fmt.Printf("\nЗащита от атаки Ферма:")
	fmt.Printf("\n  |P - Q| > 2^(bitLength/4): %v\n", diff.Cmp(minDiff) > 0)

	// Проверка защиты от атаки Винера
	root := nthRoot(publicKey.N, 4)
	minD := new(big.Int).Div(root, big.NewInt(3))
	fmt.Printf("\nЗащита от атаки Винера:")
	fmt.Printf("\n  D > N^(1/4) / 3: %v\n", privateKey.D.Cmp(minD) > 0)

	// Шифрование и дешифрование
	fmt.Println("\n\nШифрование и дешифрование:")
	message := big.NewInt(42)
	fmt.Printf("  Исходное сообщение: %d\n", message)

	ciphertext, err := rsaService.Encrypt(message, publicKey)
	if err != nil {
		fmt.Printf("Ошибка шифрования: %v\n", err)
		return
	}
	fmt.Printf("  Зашифрованное: %d\n", ciphertext)

	decrypted, err := rsaService.Decrypt(ciphertext, privateKey)
	if err != nil {
		fmt.Printf("Ошибка дешифрования: %v\n", err)
		return
	}
	fmt.Printf("  Расшифрованное: %d\n", decrypted)
	fmt.Printf("  Совпадение: %v\n", message.Cmp(decrypted) == 0)

	// Шифрование текста
	fmt.Println("\nШифрование текстового сообщения:")
	textMessage := []byte("Hello, RSA!")
	fmt.Printf("  Исходный текст: %s\n", textMessage)

	ciphertext, err = rsaService.EncryptBytes(textMessage, publicKey)
	if err != nil {
		fmt.Printf("Ошибка шифрования: %v\n", err)
		return
	}
	fmt.Printf("  Зашифрованное: %d бит\n", ciphertext.BitLen())

	decryptedText, err := rsaService.DecryptBytes(ciphertext, privateKey)
	if err != nil {
		fmt.Printf("Ошибка дешифрования: %v\n", err)
		return
	}
	fmt.Printf("  Расшифрованное: %s\n", decryptedText)

	fmt.Println()
}

func demonstrateWienerAttack() {
	fmt.Println("--- Задание 4: Wiener Attack ---")

	// Создаем уязвимый RSA ключ с малым d для демонстрации атаки
	fmt.Println("\nСоздание уязвимого RSA ключа (с малым d)...")

	// Используем известный уязвимый пример
	// Берем большие простые числа для реалистичности
	p, _ := new(big.Int).SetString("160523347", 10)
	q, _ := new(big.Int).SetString("160584539", 10)
	n := new(big.Int).Mul(p, q)

	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	// Выбираем очень малое d для демонстрации уязвимости
	d, _ := new(big.Int).SetString("1009", 10)

	// Вычисляем e: e*d ≡ 1 (mod φ)
	ntService := numbertheory.NewService()
	result := ntService.ExtendedGCD(d, phi)
	e := new(big.Int).Set(result.X)
	if e.Cmp(big.NewInt(0)) < 0 {
		e.Add(e, phi)
	}

	fmt.Printf("Уязвимый ключ:\n")
	fmt.Printf("  P = %d\n", p)
	fmt.Printf("  Q = %d\n", q)
	fmt.Printf("  N = %d (%d бит)\n", n, n.BitLen())
	fmt.Printf("  E = %d (%d бит)\n", e, e.BitLen())
	fmt.Printf("  D = %d (малое значение!)\n", d)

	// Проверяем условие для атаки Винера
	// d < N^(1/4) / 3
	nRoot := nthRoot(n, 4)
	threshold := new(big.Int).Div(nRoot, big.NewInt(3))
	fmt.Printf("\nПроверка уязвимости (d < N^(1/4)/3):")
	fmt.Printf("\n  d = %d\n", d)
	fmt.Printf("  N^(1/4)/3 ≈ %d\n", threshold)
	fmt.Printf("  Уязвимость: %v\n", d.Cmp(threshold) < 0)

	// Выполняем атаку Винера
	fmt.Println("\nВыполнение атаки Винера...")
	wienerService := attack.NewWienerService()
	attackResult, err := wienerService.Attack(e, n)

	if err != nil {
		fmt.Printf("Атака не удалась: %v\n", err)
		fmt.Println("(Это нормально для защищенных ключей)")
		return
	}

	fmt.Println("\nАтака успешна!")
	fmt.Printf("\nНайденные значения:\n")
	fmt.Printf("  D (закрытая экспонента): %d\n", attackResult.D)
	fmt.Printf("  φ(N): %d\n", attackResult.Phi)
	fmt.Printf("  P: %d\n", attackResult.P)
	fmt.Printf("  Q: %d\n", attackResult.Q)

	fmt.Printf("\nВсего вычислено подходящих дробей: %d\n", len(attackResult.ConvergentFractions))
	fmt.Println("\nПервые 10 подходящих дробей:")
	for i := 0; i < 10 && i < len(attackResult.ConvergentFractions); i++ {
		cf := attackResult.ConvergentFractions[i]
		fmt.Printf("  %d/%d\n", cf.K, cf.D)
	}

	// Проверка
	fmt.Println("\nПроверка найденных значений:")
	checkPQ := new(big.Int).Mul(attackResult.P, attackResult.Q)
	fmt.Printf("  P × Q = N: %v\n", checkPQ.Cmp(n) == 0)

	checkED := new(big.Int).Mul(e, attackResult.D)
	checkED.Mod(checkED, attackResult.Phi)
	fmt.Printf("  E × D mod φ(N) = 1: %v\n", checkED.Cmp(big.NewInt(1)) == 0)

	fmt.Println()
}

// nthRoot вычисляет целый n-й корень из x методом Ньютона
func nthRoot(x *big.Int, n int) *big.Int {
	if x.Cmp(big.NewInt(0)) <= 0 {
		return big.NewInt(0)
	}

	guess := new(big.Int).Div(x, big.NewInt(2))
	nBig := big.NewInt(int64(n))
	nMinus1 := big.NewInt(int64(n - 1))

	for i := 0; i < 100; i++ {
		pow := new(big.Int).Exp(guess, nMinus1, nil)
		term1 := new(big.Int).Mul(nMinus1, guess)
		term2 := new(big.Int).Div(x, pow)
		guessNew := new(big.Int).Add(term1, term2)
		guessNew.Div(guessNew, nBig)

		if guessNew.Cmp(guess) >= 0 {
			break
		}

		guess = guessNew
	}

	return guess
}
