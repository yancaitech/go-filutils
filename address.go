package filutils

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/multiformats/go-varint"
	cbg "github.com/whyrusleeping/cbor-gen"
	"github.com/yancaitech/go-ethereum/crypto/blake2b"
	"golang.org/x/xerrors"
)

var (
	// ErrUnknownNetwork is returned when encountering an unknown network in an address.
	ErrUnknownNetwork = errors.New("unknown address network")

	// ErrUnknownProtocol is returned when encountering an unknown protocol in an address.
	ErrUnknownProtocol = errors.New("unknown address protocol")
	// ErrInvalidPayload is returned when encountering an invalid address payload.
	ErrInvalidPayload = errors.New("invalid address payload")
	// ErrInvalidLength is returned when encountering an address of invalid length.
	ErrInvalidLength = errors.New("invalid address length")
	// ErrInvalidChecksum is returned when encountering an invalid address checksum.
	ErrInvalidChecksum = errors.New("invalid address checksum")
)

// UndefAddressString is the string used to represent an empty address when encoded to a string.
var UndefAddressString = "<empty>"

// PayloadHashLength defines the hash length taken over addresses using the Actor and SECP256K1 protocols.
const PayloadHashLength = 20

// ChecksumHashLength defines the hash length used for calculating address checksums.
const ChecksumHashLength = 4

// MaxAddressStringLength is the max length of an address encoded as a string
// it include the network prefx, protocol, and bls publickey
const MaxAddressStringLength = 2 + 84

// BlsPublicKeyBytes is the length of a BLS public key
const BlsPublicKeyBytes = 48

// BlsPrivateKeyBytes is the length of a BLS private key
const BlsPrivateKeyBytes = 32

const encodeStd = "abcdefghijklmnopqrstuvwxyz234567"

// AddressEncoding defines the base32 config used for address encoding and decoding.
var AddressEncoding = base32.NewEncoding(encodeStd)

// Address is the go type that represents an address in the filecoin network.
type Address struct{ str string }

// Undef is the type that represents an undefined address.
var Undef = Address{}

// Network represents which network an address belongs to.
type Network = byte

const (
	// Mainnet is the main network.
	Mainnet Network = iota
	// Testnet is the test network.
	Testnet
)

// MainnetPrefix is the main network prefix.
const MainnetPrefix = "f"

// TestnetPrefix is the main network prefix.
const TestnetPrefix = "t"

// Protocol represents which protocol an address uses.
type Protocol = byte

const (
	// ID represents the address ID protocol.
	ID Protocol = iota
	// SECP256K1 represents the address SECP256K1 protocol.
	SECP256K1
	// Actor represents the address Actor protocol.
	Actor
	// BLS represents the address BLS protocol.
	BLS
)

// Protocol returns the protocol used by the address.
func (a Address) Protocol() Protocol {
	return a.str[0]
}

// Payload returns the payload of the address.
func (a Address) Payload() []byte {
	return []byte(a.str[1:])
}

// Bytes returns the address as bytes.
func (a Address) Bytes() []byte {
	return []byte(a.str)
}

// String returns an address encoded as a string.
func (a Address) String() string {
	str, err := encode(Testnet, a)
	if err != nil {
		panic(err) // I don't know if this one is okay
	}
	return str
}

// Empty returns true if the address is empty, false otherwise.
func (a Address) Empty() bool {
	return a == Undef
}

// UnmarshalJSON implements the json unmarshal interface.
func (a *Address) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	addr, err := decode(s)
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// MarshalJSON implements the json marshal interface.
func (a Address) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

// Scan func
func (a *Address) Scan(value interface{}) error {
	switch value := value.(type) {
	case string:
		a1, err := decode(value)
		if err != nil {
			return err
		}

		*a = a1

		return nil
	default:
		return xerrors.New("non-string types unsupported")
	}
}

// NewIDAddress returns an address using the ID protocol.
func NewIDAddress(id uint64) (Address, error) {
	return newAddress(ID, varint.ToUvarint(id))
}

// NewSecp256k1Address returns an address using the SECP256K1 protocol.
func NewSecp256k1Address(pubkey []byte) (Address, error) {
	return newAddress(SECP256K1, addressHash(pubkey))
}

// NewActorAddress returns an address using the Actor protocol.
func NewActorAddress(data []byte) (Address, error) {
	return newAddress(Actor, addressHash(data))
}

// NewBLSAddress returns an address using the BLS protocol.
func NewBLSAddress(pubkey []byte) (Address, error) {
	return newAddress(BLS, pubkey)
}

// NewFromString returns the address represented by the string `addr`.
func NewFromString(addr string) (Address, error) {
	return decode(addr)
}

// NewFromBytes return the address represented by the bytes `addr`.
func NewFromBytes(addr []byte) (Address, error) {
	if len(addr) == 0 {
		return Undef, nil
	}
	if len(addr) == 1 {
		return Undef, ErrInvalidLength
	}
	return newAddress(addr[0], addr[1:])
}

// Checksum returns the checksum of `ingest`.
func Checksum(ingest []byte) []byte {
	return hash(ingest, ChecksumHashLength)
}

// ValidateChecksum returns true if the checksum of `ingest` is equal to `expected`>
func ValidateChecksum(ingest, expect []byte) bool {
	digest := Checksum(ingest)
	return bytes.Equal(digest, expect)
}

func addressHash(ingest []byte) []byte {
	return hash(ingest, PayloadHashLength)
}

func newAddress(protocol Protocol, payload []byte) (Address, error) {
	switch protocol {
	case ID:
		_, n, err := varint.FromUvarint(payload)
		if err != nil {
			return Undef, xerrors.Errorf("could not decode: %v: %w", err, ErrInvalidPayload)
		}
		if n != len(payload) {
			return Undef, xerrors.Errorf("different varint length (v:%d != p:%d): %w",
				n, len(payload), ErrInvalidPayload)
		}
	case SECP256K1, Actor:
		if len(payload) != PayloadHashLength {
			return Undef, ErrInvalidPayload
		}
	case BLS:
		if len(payload) != BlsPublicKeyBytes {
			return Undef, ErrInvalidPayload
		}
	}
	explen := 1 + len(payload)
	buf := make([]byte, explen)

	buf[0] = protocol
	copy(buf[1:], payload)

	return Address{string(buf)}, nil
}

func encode(network Network, addr Address) (string, error) {
	if addr == Undef {
		return UndefAddressString, nil
	}
	var ntwk string
	switch network {
	case Mainnet:
		ntwk = MainnetPrefix
	case Testnet:
		ntwk = TestnetPrefix
	}

	var strAddr string
	switch addr.Protocol() {
	case SECP256K1, Actor, BLS:
		cksm := Checksum(append([]byte{addr.Protocol()}, addr.Payload()...))
		strAddr = ntwk + fmt.Sprintf("%d", addr.Protocol()) + AddressEncoding.WithPadding(-1).EncodeToString(append(addr.Payload(), cksm[:]...))
	case ID:
		i, n, err := varint.FromUvarint(addr.Payload())
		if err != nil {
			return UndefAddressString, xerrors.Errorf("could not decode varint: %w", err)
		}
		if n != len(addr.Payload()) {
			return UndefAddressString, xerrors.Errorf("payload contains additional bytes")
		}
		strAddr = fmt.Sprintf("%s%d%d", ntwk, addr.Protocol(), i)
	}
	return strAddr, nil
}

func decode(a string) (Address, error) {
	if len(a) == 0 {
		return Undef, nil
	}
	if a == UndefAddressString {
		return Undef, nil
	}
	if len(a) > MaxAddressStringLength || len(a) < 3 {
		return Undef, ErrInvalidLength
	}

	var protocol Protocol
	switch a[1] {
	case '0':
		protocol = ID
	case '1':
		protocol = SECP256K1
	case '2':
		protocol = Actor
	case '3':
		protocol = BLS
	}

	raw := a[2:]
	if protocol == ID {
		// 20 is length of math.MaxUint64 as a string
		if len(raw) > 20 {
			return Undef, ErrInvalidLength
		}
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return Undef, ErrInvalidPayload
		}
		return newAddress(protocol, varint.ToUvarint(id))
	}

	payloadcksm, err := AddressEncoding.WithPadding(-1).DecodeString(raw)
	if err != nil {
		return Undef, err
	}
	payload := payloadcksm[:len(payloadcksm)-ChecksumHashLength]
	cksm := payloadcksm[len(payloadcksm)-ChecksumHashLength:]

	if protocol == SECP256K1 || protocol == Actor {
		if len(payload) != 20 {
			return Undef, ErrInvalidPayload
		}
	}

	if !ValidateChecksum(append([]byte{protocol}, payload...), cksm) {
		return Undef, ErrInvalidChecksum
	}

	return newAddress(protocol, payload)
}

func hash(ingest []byte, cfg int) []byte {
	hasher, err := blake2b.New(cfg, nil)
	if err != nil {
		// If this happens sth is very wrong.
		panic(fmt.Sprintf("invalid address hash configuration: %v", err)) // ok
	}
	if _, err := hasher.Write(ingest); err != nil {
		// blake2bs Write implementation never returns an error in its current
		// setup. So if this happens sth went very wrong.
		panic(fmt.Sprintf("blake2b is unable to process hashes: %v", err)) // ok
	}
	return hasher.Sum(nil)
}

// MarshalBinary func
func (a Address) MarshalBinary() ([]byte, error) {
	return a.Bytes(), nil
}

// UnmarshalBinary func
func (a *Address) UnmarshalBinary(b []byte) error {
	newAddr, err := NewFromBytes(b)
	if err != nil {
		return err
	}
	*a = newAddr
	return nil
}

// MarshalCBOR func
func (a Address) MarshalCBOR(w io.Writer) error {
	if a == Undef {
		return fmt.Errorf("cannot marshal undefined address")
	}

	if err := cbg.WriteMajorTypeHeader(w, cbg.MajByteString, uint64(len(a.str))); err != nil {
		return err
	}

	if _, err := io.WriteString(w, a.str); err != nil {
		return err
	}

	return nil
}

// UnmarshalCBOR func
func (a *Address) UnmarshalCBOR(br io.Reader) error {
	maj, extra, err := cbg.CborReadHeader(br)
	if err != nil {
		return err
	}

	if maj != cbg.MajByteString {
		return fmt.Errorf("cbor type for address unmarshal was not byte string")
	}

	if extra > 64 {
		return fmt.Errorf("too many bytes to unmarshal for an address")
	}

	buf := make([]byte, int(extra))
	if _, err := io.ReadFull(br, buf); err != nil {
		return err
	}

	addr, err := NewFromBytes(buf)
	if err != nil {
		return err
	}
	if addr == Undef {
		return fmt.Errorf("cbor input should not contain empty addresses")
	}

	*a = addr

	return nil
}
