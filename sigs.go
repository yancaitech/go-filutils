package filutils

import (
	"fmt"

	"golang.org/x/xerrors"
)

// Sign takes in signature type, private key and message. Returns a signature for that message.
// Valid sigTypes are: "secp256k1" and "bls"
func Sign(sigType SigType, privkey []byte, msg []byte) (*Signature, error) {
	sv, ok := sigs[sigType]
	if !ok {
		return nil, fmt.Errorf("cannot sign message with signature of unsupported type: %v", sigType)
	}

	sb, err := sv.Sign(privkey, msg)
	if err != nil {
		return nil, err
	}
	return &Signature{
		Type: sigType,
		Data: sb,
	}, nil
}

// Verify verifies signatures
func Verify(sig *Signature, addr Address, msg []byte) error {
	if sig == nil {
		return xerrors.Errorf("signature is nil")
	}

	if addr.Protocol() == ID {
		return fmt.Errorf("must resolve ID addresses before using them to verify a signature")
	}

	sv, ok := sigs[sig.Type]
	if !ok {
		return fmt.Errorf("cannot verify signature of unsupported type: %v", sig.Type)
	}

	return sv.Verify(sig.Data, addr, msg)
}

// Generate generates private key of given type
func Generate(sigType SigType) ([]byte, error) {
	sv, ok := sigs[sigType]
	if !ok {
		return nil, fmt.Errorf("cannot generate private key of unsupported type: %v", sigType)
	}

	return sv.GenPrivate()
}

// ToPublic converts private key to public key
func ToPublic(sigType SigType, pk []byte) ([]byte, error) {
	sv, ok := sigs[sigType]
	if !ok {
		return nil, fmt.Errorf("cannot generate public key of unsupported type: %v", sigType)
	}

	return sv.ToPublic(pk)
}

// SigShim is used for introducing signature functions
type SigShim interface {
	GenPrivate() ([]byte, error)
	ToPublic(pk []byte) ([]byte, error)
	Sign(pk []byte, msg []byte) ([]byte, error)
	Verify(sig []byte, a Address, msg []byte) error
}

var sigs map[SigType]SigShim

// RegisterSig should be only used during init
func RegisterSignature(typ SigType, vs SigShim) {
	if sigs == nil {
		sigs = make(map[SigType]SigShim)
	}
	sigs[typ] = vs
}
