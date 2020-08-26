package filutils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func TestKeyGenerator(t *testing.T) {
	k, err := GenerateKey()

	pk := "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a22657a6e453338794c5363777541696a77756776614f6e6358786d5775744b46345857434e382b546d4c4f493d227d"
	k, err = LoadKeyInfo(pk)
	fmt.Println(k.Address, err)

	//bs, err := hex.DecodeString(pk)
	//k, err = LoadKeyFromHex(bs)
	//fmt.Println(k.Address, err)

	info, err := k.DumpKeyInfo()
	fmt.Println(info)

	sk, err := k.DumpPrivateKey()
	fmt.Println(sk)
	k2, err := LoadFromPrivateKey(sk)
	fmt.Println(k2.Address, err)

	val := NewIntUnsigned(4)
	gp := NewInt(0)
	nonce := uint64(3)
	param := []byte("thomas92911")
	raw, err := CreateTransaction("t1mmou2hokfgy7cl5yzloevpesj6sbhh7itdaicoa", "t1i7qrxnrkti2eqzmnhatvw3jxiwrhke2y5o7w5ky",
		val, 1000000, gp, nonce, 0, param)
	fmt.Println(raw)

	tx, err := DecodeTransaction(raw)
	fmt.Println(tx, err)

	stx, err := SignMessage(sk, tx)
	fmt.Println(tx.Cid(), stx, err, len(stx.Signature.Data))

	bs, err := json.MarshalIndent(stx, "", "  ")
	raw = string(bs)
	fmt.Println(raw, err)

	err = json.Unmarshal(bs, stx)
	fmt.Println(stx, err)

	bs, err = stx.Serialize()
	raw = hex.EncodeToString(bs)
	fmt.Println(raw, err)

	stx, err = DecodeSignedTransaction(raw)
	fmt.Println(raw, err)

	//addr := Address{"t1krjaiug7pg52mcds7nw6rh6qftuik6gzmfvsuwq"}
	pubk := hex.EncodeToString(k.PublicKey)
	err = stx.Verify(pubk)
	fmt.Println(err)
}
