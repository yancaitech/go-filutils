package filutils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	block "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"
)

// MessageVersion define
const MessageVersion = 0

// Tx struct
type Tx struct {
	Version int64

	To   Address
	From Address

	Nonce uint64

	Value Int

	GasPrice Int
	GasLimit int64

	Method uint64
	Params []byte
}

// CreateTransaction func
func CreateTransaction(fromAddr string, toAddr string, val Int, gl int64, gp Int, nonce uint64,
	method uint64, params []byte) (raw string, err error) {
	var fa Address
	err = fa.Scan(fromAddr)
	if err != nil {
		return "", err
	}
	var ta Address
	err = ta.Scan(toAddr)
	if err != nil {
		return "", err
	}
	tx := &Tx{
		From:     fa,
		To:       ta,
		Nonce:    nonce,
		Value:    val,
		GasLimit: gl,
		GasPrice: gp,
		Method:   method,
		Params:   params,
	}
	bs, err := tx.Serialize()
	if err != nil {
		return "", err
	}
	raw = hex.EncodeToString(bs)
	return raw, nil
}

// DecodeTransaction func
func DecodeTransaction(raw string) (*Tx, error) {
	bs, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var msg Tx
	if err := msg.UnmarshalCBOR(bytes.NewReader(bs)); err != nil {
		return nil, err
	}
	if msg.Version != MessageVersion {
		return nil, fmt.Errorf("decoded message had incorrect version (%d)", msg.Version)
	}
	return &msg, nil
}

// ToStorageBlock func
func (m *Tx) ToStorageBlock() (block.Block, error) {
	data, err := m.Serialize()
	if err != nil {
		return nil, err
	}

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.BLAKE2B_MIN+31)
	c, err := pref.Sum(data)
	if err != nil {
		return nil, err
	}

	return block.NewBlockWithCid(data, c)
}

// Cid func
func (m *Tx) Cid() cid.Cid {
	b, err := m.ToStorageBlock()
	if err != nil {
		// I think this is maybe sketchy, what happens if we try to serialize a message with an undefined address in it?
		panic(fmt.Sprintf("failed to marshal message: %s", err))
	}

	return b.Cid()
}

// Serialize func
func (m *Tx) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := m.MarshalCBOR(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var lengthBufMessage = []byte{137}

// MarshalCBOR func
func (m *Tx) MarshalCBOR(w io.Writer) error {
	if m == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	if _, err := w.Write(lengthBufMessage); err != nil {
		return err
	}

	scratch := make([]byte, 9)

	// m.Version (int64) (int64)
	if m.Version >= 0 {
		if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(m.Version)); err != nil {
			return err
		}
	} else {
		if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajNegativeInt, uint64(-m.Version-1)); err != nil {
			return err
		}
	}

	// m.To (address.Address) (struct)
	if err := m.To.MarshalCBOR(w); err != nil {
		return err
	}

	// m.From (address.Address) (struct)
	if err := m.From.MarshalCBOR(w); err != nil {
		return err
	}

	// m.Nonce (uint64) (uint64)

	if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(m.Nonce)); err != nil {
		return err
	}

	// m.Value (big.Int) (struct)
	if err := m.Value.MarshalCBOR(w); err != nil {
		return err
	}

	// m.GasPrice (big.Int) (struct)
	if err := m.GasPrice.MarshalCBOR(w); err != nil {
		return err
	}

	// m.GasLimit (int64) (int64)
	if m.GasLimit >= 0 {
		if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(m.GasLimit)); err != nil {
			return err
		}
	} else {
		if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajNegativeInt, uint64(-m.GasLimit-1)); err != nil {
			return err
		}
	}

	// m.Method (abi.MethodNum) (uint64)

	if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajUnsignedInt, uint64(m.Method)); err != nil {
		return err
	}

	// m.Params ([]uint8) (slice)
	if len(m.Params) > cbg.ByteArrayMaxLen {
		return xerrors.Errorf("Byte array in field t.Params was too long")
	}

	if err := cbg.WriteMajorTypeHeaderBuf(scratch, w, cbg.MajByteString, uint64(len(m.Params))); err != nil {
		return err
	}

	if _, err := w.Write(m.Params); err != nil {
		return err
	}
	return nil
}

// UnmarshalCBOR func
func (m *Tx) UnmarshalCBOR(r io.Reader) error {
	br := cbg.GetPeeker(r)
	scratch := make([]byte, 8)

	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
	if err != nil {
		return err
	}
	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 9 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// m.Version (int64) (int64)
	{
		maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
		var extraI int64
		if err != nil {
			return err
		}
		switch maj {
		case cbg.MajUnsignedInt:
			extraI = int64(extra)
			if extraI < 0 {
				return fmt.Errorf("int64 positive overflow")
			}
		case cbg.MajNegativeInt:
			extraI = int64(extra)
			if extraI < 0 {
				return fmt.Errorf("int64 negative oveflow")
			}
			extraI = -1 - extraI
		default:
			return fmt.Errorf("wrong type for int64 field: %d", maj)
		}

		m.Version = int64(extraI)
	}
	// m.To (address.Address) (struct)

	{

		if err := m.To.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling m.To: %w", err)
		}

	}
	// m.From (address.Address) (struct)

	{

		if err := m.From.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling m.From: %w", err)
		}

	}
	// m.Nonce (uint64) (uint64)

	{

		maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for uint64 field")
		}
		m.Nonce = uint64(extra)

	}
	// m.Value (big.Int) (struct)

	{

		if err := m.Value.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.Value: %w", err)
		}

	}
	// m.GasPrice (big.Int) (struct)

	{

		if err := m.GasPrice.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling m.GasPrice: %w", err)
		}

	}
	// m.GasLimit (int64) (int64)
	{
		maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
		var extraI int64
		if err != nil {
			return err
		}
		switch maj {
		case cbg.MajUnsignedInt:
			extraI = int64(extra)
			if extraI < 0 {
				return fmt.Errorf("int64 positive overflow")
			}
		case cbg.MajNegativeInt:
			extraI = int64(extra)
			if extraI < 0 {
				return fmt.Errorf("int64 negative oveflow")
			}
			extraI = -1 - extraI
		default:
			return fmt.Errorf("wrong type for int64 field: %d", maj)
		}

		m.GasLimit = int64(extraI)
	}
	// m.Method (abi.MethodNum) (uint64)

	{

		maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for uint64 field")
		}
		m.Method = uint64(extra)

	}
	// m.Params ([]uint8) (slice)

	maj, extra, err = cbg.CborReadHeaderBuf(br, scratch)
	if err != nil {
		return err
	}

	if extra > cbg.ByteArrayMaxLen {
		return fmt.Errorf("m.Params: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}
	m.Params = make([]byte, extra)
	if _, err := io.ReadFull(br, m.Params); err != nil {
		return err
	}
	return nil
}

var lengthBufSignedMessage = []byte{130}

// SignedMessage struct
type SignedMessage struct {
	Message   Tx
	Signature Signature
}

// Serialize func
func (t *SignedMessage) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := t.MarshalCBOR(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeSignedTransaction func
func DecodeSignedTransaction(raw string) (*SignedMessage, error) {
	bs, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var msg SignedMessage
	if err := msg.UnmarshalCBOR(bytes.NewReader(bs)); err != nil {
		return nil, err
	}
	if msg.Message.Version != MessageVersion {
		return nil, fmt.Errorf("decoded message had incorrect version (%d)", msg.Message.Version)
	}
	return &msg, nil
}

// MarshalCBOR func
func (t *SignedMessage) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	if _, err := w.Write(lengthBufSignedMessage); err != nil {
		return err
	}

	// t.Message (types.Message) (struct)
	if err := t.Message.MarshalCBOR(w); err != nil {
		return err
	}

	// t.Signature (crypto.Signature) (struct)
	if err := t.Signature.MarshalCBOR(w); err != nil {
		return err
	}
	return nil
}

// UnmarshalCBOR func
func (t *SignedMessage) UnmarshalCBOR(r io.Reader) error {
	br := cbg.GetPeeker(r)
	scratch := make([]byte, 8)

	maj, extra, err := cbg.CborReadHeaderBuf(br, scratch)
	if err != nil {
		return err
	}
	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 2 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Message (types.Message) (struct)

	{

		if err := t.Message.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.Message: %w", err)
		}

	}
	// t.Signature (crypto.Signature) (struct)

	{

		if err := t.Signature.UnmarshalCBOR(br); err != nil {
			return xerrors.Errorf("unmarshaling t.Signature: %w", err)
		}

	}
	return nil
}

// Verify message
func (t *SignedMessage) Verify(pubk string) error {
	mcid := t.Message.Cid()
	sig := t.Signature.Data
	err := Verify(sig, pubk, mcid.Bytes())
	return err
}

// SignMessage func
func SignMessage(privk string, msg *Tx) (sm *SignedMessage, err error) {
	pk, err := hex.DecodeString(privk)
	if err != nil {
		return nil, err
	}
	mcid := msg.Cid()
	sb, err := Sign(pk, mcid.Bytes())
	if err != nil {
		return nil, err
	}
	sig := &Signature{
		Type: SigTypeSecp256k1,
		Data: sb,
	}
	return &SignedMessage{
		Message:   *msg,
		Signature: *sig,
	}, nil
}

// Cid func
func (t *SignedMessage) Cid() cid.Cid {
	sb, err := t.ToStorageBlock()
	if err != nil {
		panic(err)
	}

	return sb.Cid()
}

// ToStorageBlock func
func (t *SignedMessage) ToStorageBlock() (block.Block, error) {
	data, err := t.Serialize()
	if err != nil {
		return nil, err
	}

	pref := cid.NewPrefixV1(cid.DagCBOR, multihash.BLAKE2B_MIN+31)
	c, err := pref.Sum(data)
	if err != nil {
		return nil, err
	}

	return block.NewBlockWithCid(data, c)
}
