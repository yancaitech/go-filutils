package filutils

import (
	"golang.org/x/xerrors"
)

const (
	// KTBLS type
	KTBLS = "bls"
	// KTSecp256k1 type
	KTSecp256k1 = "secp256k1"
)

// KeyInfo is used for storing keys in KeyStore
type KeyInfo struct {
	Type       string
	PrivateKey []byte
}

// Key struct
type Key struct {
	KeyInfo

	PublicKey []byte
	Address   Address
}

// GenerateKey func
func GenerateKey(typ SigType) (*Key, error) {
	pk, err := Generate(typ)
	if err != nil {
		return nil, err
	}
	ki := KeyInfo{
		Type:       kstoreSigType(typ),
		PrivateKey: pk,
	}
	return NewKey(ki)
}

// NewKey func
func NewKey(keyinfo KeyInfo) (*Key, error) {
	k := &Key{
		KeyInfo: keyinfo,
	}

	var err error
	k.PublicKey, err = ToPublic(ActSigType(k.Type), k.PrivateKey)
	if err != nil {
		return nil, err
	}

	switch k.Type {
	case KTSecp256k1:
		k.Address, err = NewSecp256k1Address(k.PublicKey)
		if err != nil {
			return nil, xerrors.Errorf("converting Secp256k1 to address: %w", err)
		}
	case KTBLS:
		k.Address, err = NewBLSAddress(k.PublicKey)
		if err != nil {
			return nil, xerrors.Errorf("converting BLS to address: %w", err)
		}
	default:
		return nil, xerrors.Errorf("unknown key type")
	}
	return k, nil

}

func kstoreSigType(typ SigType) string {
	switch typ {
	case SigTypeBLS:
		return KTBLS
	case SigTypeSecp256k1:
		return KTSecp256k1
	default:
		return ""
	}
}

// ActSigType func
func ActSigType(typ string) SigType {
	switch typ {
	case KTBLS:
		return SigTypeBLS
	case KTSecp256k1:
		return SigTypeSecp256k1
	default:
		return 0
	}
}
