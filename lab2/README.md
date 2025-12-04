# Лабораторная работа 2: Криптографические алгоритмы

Реализация криптографических алгоритмов теории чисел, тестов простоты, RSA шифрования и атаки Винера на языке Go.

## Структура проекта

```
lab2/
├── cmd/
│   └── demo/
│       └── main.go                 # Демонстрация работы всех компонентов
├── internal/
│   ├── numbertheory/              # Задание 1: базовые операции теории чисел
│   │   ├── service.go
│   │   ├── euclid.go
│   │   ├── symbols.go
│   │   ├── modexp.go
│   │   └── service_test.go
│   ├── primality/                 # Задание 2: тесты простоты
│   │   ├── interface.go
│   │   ├── base.go
│   │   ├── fermat.go
│   │   ├── solovay_strassen.go
│   │   ├── miller_rabin.go
│   │   └── primality_test.go
│   ├── rsa/                       # Задание 3: RSA шифрование
│   │   ├── service.go
│   │   ├── keygen.go
│   │   ├── types.go
│   │   └── rsa_test.go
│   └── attack/                    # Задание 4: атака Винера
│       ├── wiener.go
│       ├── continued_fraction.go
│       └── wiener_test.go
├── go.mod
└── README.md
```

## Задание 1: Number Theory Service

Stateless-сервис с компонентным функционалом для операций теории чисел.

### Возможности:

- **Символ Лежандра**: `LegendreSymbol(a, p)` - вычисление символа Лежандра (a/p)
- **Символ Якоби**: `JacobiSymbol(a, n)` - вычисление символа Якоби (a/n)
- **НОД**: `GCD(a, b)` - алгоритм Евклида
- **Расширенный НОД**: `ExtendedGCD(a, b)` - расширенный алгоритм Евклида с решением соотношения Безу
- **Модульное возведение в степень**: `ModExp(base, exp, mod)` - быстрое возведение в степень по модулю

### Пример использования:

```go
ntService := numbertheory.NewService()

// Символ Лежандра
legendre := ntService.LegendreSymbol(big.NewInt(7), big.NewInt(13))

// НОД
gcd := ntService.GCD(big.NewInt(48), big.NewInt(18))

// Расширенный НОД
result := ntService.ExtendedGCD(big.NewInt(240), big.NewInt(46))
// result.GCD, result.X, result.Y

// Возведение в степень по модулю
modExp := ntService.ModExp(big.NewInt(3), big.NewInt(7), big.NewInt(13))
```

## Задание 2: Primality Tests

Вероятностные тесты простоты с использованием паттерна "Шаблонный метод" (Template Method).

### Реализованные тесты:

1. **Тест Ферма** (`FermatTest`)
   - Проверяет: a^(n-1) ≡ 1 (mod n)

2. **Тест Соловея-Штрассена** (`SolovayStrassenTest`)
   - Проверяет: a^((n-1)/2) ≡ J(a,n) (mod n)
   - Использует символ Якоби

3. **Тест Миллера-Рабина** (`MillerRabinTest`)
   - Наиболее надежный тест
   - Представляет n-1 как 2^s * d

### Пример использования:

```go
// Создаем тест
test := primality.NewMillerRabinTest()

// Проверяем число на простоту с вероятностью 99%
isPrime := test.IsProbablyPrime(big.NewInt(17), 0.99)
```

### Архитектура:

- **Interface**: `PrimalityTester` - интерфейс для всех тестов
- **Base class**: `BasePrimalityTest` - базовый класс с Template Method
- **Implementations**: Ферма, Соловея-Штрассена, Миллера-Рабина

## Задание 3: RSA Service

Объектный сервис для шифрования и дешифрования алгоритмом RSA.

### Возможности:

- Генерация ключей с выбором теста простоты
- Защита от атаки Ферма: |p - q| > 2^(bitLength/4)
- Защита от атаки Винера: d > N^(1/4) / 3
- Шифрование и дешифрование данных

### Nested компоненты:

- **TestType** (enum): Fermat, SolovayStrassen, MillerRabin
- **KeyGenerator**: Генерация ключей с заданными параметрами

### Пример использования:

```go
// Создаем RSA сервис
rsaService := rsa.NewService(
    rsa.TestTypeMillerRabin, // тест простоты
    0.99,                     // минимальная вероятность простоты
    512,                      // битовая длина
)

// Генерируем ключи
err := rsaService.GenerateKeys()

// Получаем ключи
publicKey, _ := rsaService.GetPublicKey()
privateKey, _ := rsaService.GetPrivateKey()

// Шифруем
message := big.NewInt(42)
ciphertext, _ := rsaService.Encrypt(message, publicKey)

// Дешифруем
decrypted, _ := rsaService.Decrypt(ciphertext, privateKey)
```

## Задание 4: Wiener Attack

Реализация атаки Винера на уязвимые открытые ключи RSA.

### Принцип работы:

1. Разложение e/N в цепную дробь
2. Вычисление подходящих дробей
3. Поиск закрытой экспоненты d
4. Факторизация модуля N

### Результат атаки:

- Закрытая экспонента `d`
- Функция Эйлера `φ(n)`
- Простые числа `p` и `q`
- Все вычисленные подходящие дроби

### Пример использования:

```go
wienerService := attack.NewWienerService()

// Выполняем атаку на уязвимый ключ
result, err := wienerService.Attack(e, N)

if err == nil {
    fmt.Printf("Найдена закрытая экспонента: %d\n", result.D)
    fmt.Printf("φ(N) = %d\n", result.Phi)
    fmt.Printf("P = %d, Q = %d\n", result.P, result.Q)
}
```

## Установка и запуск

### Требования:

- Go 1.21 или выше

### Запуск демонстрации:

```bash
cd lab2
go run cmd/demo/main.go
```

### Запуск тестов:

```bash
# Все тесты
go test ./...

# Конкретный пакет
go test ./internal/numbertheory
go test ./internal/primality
go test ./internal/rsa
go test ./internal/attack

# С подробным выводом
go test -v ./...
```

## Особенности реализации

### Безопасность:

1. **Собственные реализации**: Все алгоритмы реализованы без использования сторонних криптографических библиотек
2. **Защита от атак**: RSA ключи генерируются с проверкой защиты от атак Ферма и Винера
3. **Вероятностная проверка**: Настраиваемая вероятность правильности тестов простоты

### Паттерны проектирования:

1. **Template Method**: Базовый класс для тестов простоты с кастомизируемой итерацией
2. **Strategy**: Выбор теста простоты через enum
3. **Nested Types**: TestType как nested enum в RSA сервисе
4. **Service Layer**: Stateless сервисы для изолированного функционала

### Производительность:

- Быстрое возведение в степень (бинарный алгоритм)
- Эффективный алгоритм Евклида
- Оптимизированные тесты простоты с настраиваемым количеством итераций

## Примеры вывода

### Number Theory:
```
Legendre(7, 13) = -1
Jacobi(7, 45) = 1
GCD(48, 18) = 6
240 * -9 + 46 * 47 = 2
3^7 mod 13 = 3
```

### Primality Tests:
```
Miller-Rabin:
  17: true
  561: false (псевдопростое Ферма)
  1009: true
  1000: false
```

### RSA:
```
Открытый ключ:
  N: 512 бит
  E: 65537

Защита от атаки Ферма: true
Защита от атаки Винера: true

Шифрование:
  Исходное: 42
  Зашифрованное: [большое число]
  Расшифрованное: 42
  Совпадение: true
```

### Wiener Attack:
```
Атака успешна!
Найденные значения:
  D: 7
  φ(N): 10200
  P: 101
  Q: 103

Проверка:
  P × Q = N: true
  E × D mod φ(N) = 1: true
```

## Лицензия

Учебный проект для курса криптографии.
