package filutils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/blake2b"
)

// SignatureBytes is the length of a BLS signature
const SignatureBytes = 96

// PrivateKeyBytes is the length of a BLS private key
const PrivateKeyBytes = 32

// PublicKeyBytes is the length of a BLS public key
const PublicKeyBytes = 48

// DigestBytes is the length of a BLS message hash/digest
const DigestBytes = 96

// Signature is a compressed affine
//type Signature [SignatureBytes]byte

// PrivateKey is a compressed affine
type PrivateKey [PrivateKeyBytes]byte

// PublicKey is a compressed affine
type PublicKey [PublicKeyBytes]byte

// Message is a byte slice
type Message []byte

// Digest is a compressed affine
type Digest [DigestBytes]byte

// Used when generating a private key deterministically
type PrivateKeyGenSeed [32]byte

type secpSigner struct{}

// GenerateKeyFromSeed generates a new key from the given reader.
func RGenerateKeyFromSeed(seed io.Reader) ([]byte, error) {
	key, err := ecdsa.GenerateKey(btcec.S256(), seed)
	if err != nil {
		return nil, err
	}

	privkey := make([]byte, PrivateKeyBytes)
	blob := key.D.Bytes()

	// the length is guaranteed to be fixed, given the serialization rules for secp2561k curve points.
	copy(privkey[PrivateKeyBytes-len(blob):], blob)

	return privkey, nil
}

// GenerateKey creates a new key using secure randomness from crypto.rand.
func RGenerateKey() ([]byte, error) {
	return RGenerateKeyFromSeed(rand.Reader)
}

func (secpSigner) GenPrivate() ([]byte, error) {
	priv, err := RGenerateKey()
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (secpSigner) ToPublic(pk []byte) ([]byte, error) {
	return pk, nil
}

func (secpSigner) Sign(pk []byte, msg []byte) ([]byte, error) {
	b2sum := blake2b.Sum256(msg)
	prik, _ := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	s, err := prik.Sign(b2sum[:])
	if err != nil {
		return nil, err
	}
	return s.Serialize(), nil
}

func (secpSigner) Verify(sig []byte, a Address, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	s, err := btcec.ParseSignature(sig, btcec.S256())
	if err != nil {
		return err
	}

	pubk, _, err := btcec.RecoverCompact(btcec.S256(), sig, b2sum[:])
	if err != nil {
		return err
	}

	v := s.Verify(b2sum[:], pubk)
	if v == false {
		return errors.New("Verify signature failed")
	}

	return nil
}
