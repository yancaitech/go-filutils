package filutils

import (
	"fmt"
	"io"

	cbg "github.com/whyrusleeping/cbor-gen"
)

type SigType int

const (
	SigTypeSecp256k1 = SigType(iota)
	SigTypeBLS
)

func (t SigType) Name() (string, error) {
	switch t {
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

// func (s *Signature) Equals(o *Signature) bool {
// 	if s == nil || o == nil {
// 		return s == o
// 	}
// 	return s.Type == o.Type && bytes.Equal(s.Data, o.Data)
// }

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
	case SigTypeSecp256k1:
		s.Type = SigTypeSecp256k1
	case SigTypeBLS:
		s.Type = SigTypeBLS
	}
	s.Data = bs[1:]
	return nil
}

func (s *Signature) MarshalCBOR(w io.Writer) error {
	if s == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	header := cbg.CborEncodeMajorType(cbg.MajByteString, uint64(len(s.Data)+1))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(1)}); err != nil {
		return err
	}
	if _, err := w.Write(s.Data); err != nil {
		return err
	}
	return nil
}

func (s *Signature) UnmarshalCBOR(br io.Reader) error {
	maj, l, err := cbg.CborReadHeader(br)
	if err != nil {
		return err
	}

	if maj != cbg.MajByteString {
		return fmt.Errorf("cbor input for signature was not a byte string")
	}
	if l > SignatureMaxLength {
		return fmt.Errorf("cbor byte array for signature was too long")
	}
	buf := make([]byte, l)
	if _, err = io.ReadFull(br, buf); err != nil {
		return err
	}
	s.Data = buf[1:]
	return nil
}
