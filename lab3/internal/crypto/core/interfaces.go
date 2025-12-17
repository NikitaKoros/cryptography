package core

// KeyExpander определяет функционал для расширения ключа
type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

// RoundEncrypter определяет функционал для раундового шифрования
type RoundEncrypter interface {
	EncryptRound(block []byte, roundKey []byte) ([]byte, error)
}

// SymmetricCipher определяет функционал симметричного шифрования
type SymmetricCipher interface {
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
	SetEncryptionKey(key []byte) error
	SetDecryptionKey(key []byte) error
	BlockSize() int
}
