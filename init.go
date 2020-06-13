package filutils

func init() {
	RegisterSignature(SigTypeBLS, blsSigner{})
	RegisterSignature(SigTypeSecp256k1, secpSigner{})
}
