package ECC

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

func CalculateYFromX(x *secp256k1.FieldVal) (*secp256k1.FieldVal, error) {
	// Curve parameters
	var p secp256k1.FieldVal
	p.SetByteSlice(secp256k1.S256().P.Bytes())

	// Compute x^3 + 7
	var xCubed, result secp256k1.FieldVal

	xCubed.SquareVal(x).Mul(x)    // x^3
	result.SetInt(7).Add(&xCubed) // x^3 + 7

	// Calculate the modular square root to find y
	var y secp256k1.FieldVal

	y.SquareRootVal(&result)

	return &y, nil
}

// modNScalarToField converts a scalar modulo the group order to a field value.
func ModNScalarToField(v *secp256k1.ModNScalar) secp256k1.FieldVal {
	var buf [32]byte
	v.PutBytes(&buf)
	var fv secp256k1.FieldVal
	fv.SetBytes(&buf)
	return fv
}
func zeroArray32(b *[32]byte) {
	zero32 := [32]byte{}
	copy(b[:], zero32[:])
}
func FieldToModNScalar(v *secp256k1.FieldVal) *secp256k1.ModNScalar {
	var buf [32]byte
	v.PutBytes(&buf)
	var s secp256k1.ModNScalar
	zeroArray32(&buf)
	return &s
}
