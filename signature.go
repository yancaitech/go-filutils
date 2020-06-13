package filutils

import (
	"bytes"
	"fmt"
	"math"
)

type SigType byte

const (
	SigTypeUnknown = SigType(math.MaxUint8)

	SigTypeSecp256k1 = SigType(iota)
	SigTypeBLS
)

func (t SigType) Name() (string, error) {
	switch t {
	case SigTypeUnknown:
		return "unknown", nil
	case SigTypeSecp256k1:
		return "secp256k1", nil
	case SigTypeBLS:
		return "bls", nil
	default:
		return "", fmt.Errorf("invalid signature type: %d", t)
	}
}

const SignatureMaxLength = 200

type Signature struct {
	Type SigType
	Data []byte
}

func (s *Signature) Equals(o *Signature) bool {
	if s == nil || o == nil {
		return s == o
	}
	return s.Type == o.Type && bytes.Equal(s.Data, o.Data)
}

func (s *Signature) MarshalBinary() ([]byte, error) {
	bs := make([]byte, len(s.Data)+1)
	bs[0] = byte(s.Type)
	copy(bs[1:], s.Data)
	return bs, nil
}

func (s *Signature) UnmarshalBinary(bs []byte) error {
	if len(bs) == 0 {
		return fmt.Errorf("invalid signature bytes of length 0")
	}
	switch SigType(bs[0]) {
	default:
		// Do not error during unmarshal but leave a standard value.
		// unmarshal(marshal(zero valued sig)) is valuable for test
		// and type needs to be checked by caller anyway.
		s.Type = SigTypeUnknown
	case SigTypeSecp256k1:
		s.Type = SigTypeSecp256k1
	case SigTypeBLS:
		s.Type = SigTypeBLS
	}
	s.Data = bs[1:]
	return nil
}
