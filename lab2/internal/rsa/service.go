package rsa

import (
	"fmt"
	"math/big"

	"github.com/nikitakorostin/cryptography/lab2/internal/numbertheory"
)

// Service предоставляет функционал для шифрования и дешифрования RSA
type Service struct {
	keyGenerator *KeyGenerator
	ntService    *numbertheory.Service
	currentKey   *PrivateKey
}

// NewService создает новый RSA сервис
func NewService(testType TestType, minProbability float64, bitLength int) *Service {
	return &Service{
		keyGenerator: NewKeyGenerator(testType, minProbability, bitLength),
		ntService:    numbertheory.NewService(),
	}
}

// GenerateKeys генерирует новую пару ключей
func (s *Service) GenerateKeys() error {
	key, err := s.keyGenerator.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("ошибка генерации ключей: %w", err)
	}

	s.currentKey = key
	return nil
}

// GetPublicKey возвращает текущий открытый ключ
func (s *Service) GetPublicKey() (*PublicKey, error) {
	if s.currentKey == nil {
		return nil, fmt.Errorf("ключи не сгенерированы")
	}

	return &s.currentKey.PublicKey, nil
}

// GetPrivateKey возвращает текущий закрытый ключ
func (s *Service) GetPrivateKey() (*PrivateKey, error) {
	if s.currentKey == nil {
		return nil, fmt.Errorf("ключи не сгенерированы")
	}

	return s.currentKey, nil
}

// Encrypt шифрует данные открытым ключом
// Формула: c = m^e mod n
func (s *Service) Encrypt(message *big.Int, publicKey *PublicKey) (*big.Int, error) {
	// Проверяем, что сообщение меньше модуля
	if message.Cmp(publicKey.N) >= 0 {
		return nil, fmt.Errorf("сообщение должно быть меньше модуля n")
	}

	// c = m^e mod n
	ciphertext := s.ntService.ModExp(message, publicKey.E, publicKey.N)
	return ciphertext, nil
}

// Decrypt дешифрует данные закрытым ключом
// Формула: m = c^d mod n
func (s *Service) Decrypt(ciphertext *big.Int, privateKey *PrivateKey) (*big.Int, error) {
	// Проверяем, что шифртекст меньше модуля
	if ciphertext.Cmp(privateKey.N) >= 0 {
		return nil, fmt.Errorf("шифртекст должен быть меньше модуля n")
	}

	// m = c^d mod n
	message := s.ntService.ModExp(ciphertext, privateKey.D, privateKey.N)
	return message, nil
}

// EncryptBytes шифрует байтовый массив
func (s *Service) EncryptBytes(data []byte, publicKey *PublicKey) (*big.Int, error) {
	message := new(big.Int).SetBytes(data)
	return s.Encrypt(message, publicKey)
}

// DecryptBytes дешифрует в байтовый массив
func (s *Service) DecryptBytes(ciphertext *big.Int, privateKey *PrivateKey) ([]byte, error) {
	message, err := s.Decrypt(ciphertext, privateKey)
	if err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}
