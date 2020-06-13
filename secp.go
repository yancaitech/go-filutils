package filutils

import (
	"fmt"

	"github.com/minio/blake2b-simd"
)

type secpSigner struct{}

func (secpSigner) GenPrivate() ([]byte, error) {
	priv, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (secpSigner) ToPublic(pk []byte) ([]byte, error) {
	return PublicKey(pk), nil
}

func (secpSigner) Sign(pk []byte, msg []byte) ([]byte, error) {
	b2sum := blake2b.Sum256(msg)
	sig, err := Sign(pk, b2sum[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (secpSigner) Verify(sig []byte, a Address, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	pubk, err := EcRecover(b2sum[:], sig)
	if err != nil {
		return err
	}

	maybeaddr, err := NewSecp256k1Address(pubk)
	if err != nil {
		return err
	}

	if a != maybeaddr {
		return fmt.Errorf("signature did not match")
	}

	return nil
}
