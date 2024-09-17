package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"math/big"

	"github.com/xdg-go/pbkdf2"
)

// GenerateAESKey generates a new AES-GCM symmetric key.
// GenerateRandomPassword generates a random password of the given length
func GenerateRandomPassword(length int) (string, error) {
	// Buat slice byte untuk menampung angka acak
	bytes := make([]byte, length)

	// Mengisi slice byte dengan angka acak yang aman secara kriptografis
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Ubah byte ke dalam bentuk hexadecimal
	return hex.EncodeToString(bytes), nil
}

// GenerateKey generates a derived key from a random password and salt using PBKDF2 with SHA-256
func GenerateKey() []byte {
	// Generate random password
	password, err := GenerateRandomPassword(16)
	if err != nil {
		log.Fatal(err)
	}

	// Generate random salt
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err) // Gunakan log.Fatal untuk menghentikan program jika terjadi error
	}

	// Derive key using PBKDF2 with SHA-256
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)

	// Return password, salt, and key as hex strings
	return key
}

// EncryptAESGCM encrypts a file using AES-GCM.
func EncryptAESGCM(plaintext []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts a ciphertext using AES-GCM.
func DecryptAESGCM(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptRSA encrypts a session key using RSA public key (N, E) as big.Int values.
func EncryptRSA(sessionKey []byte, publicKeyN string, publicKeyE string) ([]byte, error) {
	n := new(big.Int)
	e := new(big.Int)

	// Convert public key components (N and E) from string to big.Int
	n.SetString(publicKeyN, 10)
	e.SetString(publicKeyE, 10)

	// Convert the session key (AES key) to big.Int
	sessionKeyBigInt := new(big.Int).SetBytes(sessionKey)

	// Perform RSA encryption: C = M^e mod N
	encryptedSessionKeyBigInt := new(big.Int).Exp(sessionKeyBigInt, e, n)

	// Return the encrypted session key as bytes
	return encryptedSessionKeyBigInt.Bytes(), nil
}

// DecryptRSA decrypts a session key using RSA private key (N, D) as big.Int values.
func DecryptRSA(privateKeyD string, publicKeyN string, encryptedSessionKey []byte) ([]byte, error) {
	d := new(big.Int)
	n := new(big.Int)

	// Convert private key components (N and D) from string to big.Int
	d.SetString(privateKeyD, 10)
	n.SetString(publicKeyN, 10)

	// Convert encrypted session key (byte array) to big.Int
	encryptedSessionKeyBigInt := new(big.Int).SetBytes(encryptedSessionKey)

	// Perform RSA decryption: M = C^d mod N
	decryptedSessionKeyBigInt := new(big.Int).Exp(encryptedSessionKeyBigInt, d, n)

	// Return the decrypted session key as bytes
	return decryptedSessionKeyBigInt.Bytes(), nil
}
