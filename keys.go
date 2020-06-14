package filutils

import (
	"encoding/hex"
	"encoding/json"
	"strings"

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

// WalletSerializeResult struct
type WalletSerializeResult struct {
	KeyInfo []*KeyInfo
}

// DumpPrivateKey func
func (k *Key) DumpPrivateKey() (prik string, err error) {
	prik = hex.EncodeToString(k.PrivateKey)
	return prik, err
}

// LoadFromPrivateKey func
func LoadFromPrivateKey(prik string) (key *Key, err error) {
	var ki KeyInfo
	ki.Type = KTSecp256k1
	ki.PrivateKey, err = hex.DecodeString(prik)
	if err != nil {
		return nil, err
	}
	return NewKey(ki)
}

// LoadKeyInfo func
func LoadKeyInfo(info string) (*Key, error) {
	var ki KeyInfo
	bs, err := hex.DecodeString(strings.TrimSpace(info))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bs, &ki); err != nil {
		return nil, err
	}
	return NewKey(ki)
}

// DumpKeyInfo func
func (k *Key) DumpKeyInfo() (info string, err error) {
	var ki KeyInfo
	ki.Type = k.Type
	ki.PrivateKey = k.PrivateKey
	bs, err := json.Marshal(ki)
	if err != nil {
		return "", err
	}
	info = hex.EncodeToString(bs)
	return info, nil
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
