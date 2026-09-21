package vctpre

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	bn128 "pvpre/bn128"
)

// Param contains the public parameters PG = (G1, G2, GT, e, g1, g2, Z).
type Param struct {
	G1 *bn128.G1
	G2 *bn128.G2
	Z  *bn128.GT
}

type SK struct {
	A1 *big.Int
	A2 *big.Int
}

// PK is (Z^a1, g2^a2).
type PK struct {
	P1 *bn128.GT
	P2 *bn128.G2
}

// CT1 is a first-level ciphertext and CT2 is a second-level ciphertext.
type CT1 struct {
	C1 *bn128.G1
	C2 *bn128.GT
}

type CT2 struct {
	C1 *bn128.GT
	C2 *bn128.GT
}

// Proof is the Fiat-Shamir NIZK proof used to verify one re-encryption share.
type Proof struct {
	HHat *bn128.GT
	GHat *bn128.GT
	RHat *bn128.G2
}

// ReEncShare is ct(B)[l] = (C~l,1, C~l,2, l, pi).
type ReEncShare struct {
	C1    *bn128.GT
	C2    *bn128.GT
	Index int
	Proof *Proof
}

func Setup() *Param {
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	return &Param{G1: g1, G2: g2, Z: bn128.Pair(g1, g2)}
}

func randomScalar() *big.Int {
	for {
		r, _ := rand.Int(rand.Reader, bn128.Order)
		if r.Sign() != 0 {
			return r
		}
	}
}

func KeyGen(param *Param) (*SK, *PK) {
	sk := &SK{A1: randomScalar(), A2: randomScalar()}
	pk := &PK{
		P1: new(bn128.GT).ScalarMult(param.Z, sk.A1),
		P2: new(bn128.G2).ScalarMult(param.G2, sk.A2),
	}
	return sk, pk
}

func Enc1(param *Param, pk *PK, m *bn128.GT) *CT1 {
	r := randomScalar()
	return &CT1{
		C1: new(bn128.G1).ScalarMult(param.G1, r),
		C2: new(bn128.GT).Add(m, new(bn128.GT).ScalarMult(pk.P1, r)),
	}
}

func Dec1(param *Param, sk *SK, ct *CT1) *bn128.GT {
	mask := new(bn128.GT).ScalarMult(bn128.Pair(ct.C1, param.G2), sk.A1)
	return new(bn128.GT).Add(ct.C2, new(bn128.GT).Neg(mask))
}

func Enc2(param *Param, pk *PK, m *bn128.GT) *CT2 {
	r := randomScalar()
	mask := bn128.Pair(new(bn128.G1).ScalarMult(param.G1, r), pk.P2)
	return &CT2{C1: mask, C2: new(bn128.GT).Add(m, new(bn128.GT).ScalarMult(param.Z, r))}
}

func Dec2(_ *Param, sk *SK, ct *CT2) *bn128.GT {
	inv := new(big.Int).ModInverse(sk.A2, bn128.Order)
	mask := new(bn128.GT).ScalarMult(ct.C1, inv)
	return new(bn128.GT).Add(ct.C2, new(bn128.GT).Neg(mask))
}

// CKGen samples the control key used to authorize ciphertexts from A to B.
func CKGen() *big.Int {
	return randomScalar()
}

// RKShare Shamir-shares f(0) = a1(A) + ck and returns rk_l = pk(B).P2^f(l).
// commitments[i] binds the coefficient f_i under pk(B).P2 for VerifyShare.
func RKShare(param *Param, skA *SK, pkB *PK, ck *big.Int, t, n int) ([]*bn128.G2, []*bn128.GT, error) {
	if t < 1 || n < t {
		return nil, nil, errors.New("invalid threshold")
	}

	coefficients := make([]*big.Int, t)
	coefficients[0] = new(big.Int).Add(skA.A1, ck)
	coefficients[0].Mod(coefficients[0], bn128.Order)
	for i := 1; i < t; i++ {
		coefficients[i] = randomScalar()
	}

	commitments := make([]*bn128.GT, t)
	for i, coefficient := range coefficients {
		commitments[i] = bn128.Pair(param.G1, new(bn128.G2).ScalarMult(pkB.P2, coefficient))
	}

	shares := make([]*bn128.G2, n)
	for l := 1; l <= n; l++ {
		shares[l-1] = new(bn128.G2).ScalarMult(pkB.P2, evaluate(coefficients, l))
	}
	return shares, commitments, nil
}

// CTAuth re-randomizes ct(A) and attaches the delegation control key.
func CTAuth(param *Param, ct *CT1, pkA *PK, ck *big.Int) *CT1 {
	r := randomScalar()
	c1 := new(bn128.G1).Add(ct.C1, new(bn128.G1).ScalarMult(param.G1, r))
	c2 := new(bn128.GT).Add(ct.C2, new(bn128.GT).ScalarMult(pkA.P1, r))
	control := new(bn128.GT).ScalarMult(bn128.Pair(c1, param.G2), ck)
	return &CT1{C1: c1, C2: new(bn128.GT).Add(c2, control)}
}

func ReEncryptShare(param *Param, rk *bn128.G2, ct *CT1, index int) (*ReEncShare, error) {
	if index < 1 {
		return nil, errors.New("share index must be positive")
	}
	c1 := bn128.Pair(ct.C1, rk)
	proof := prove(param, param.G1, bn128.Pair(param.G1, rk), ct.C1, c1, rk)
	return &ReEncShare{C1: c1, C2: new(bn128.GT).Set(ct.C2), Index: index, Proof: proof}, nil
}

// VerifyShare checks both the copied ciphertext component and the NIZK proof.
func VerifyShare(param *Param, share *ReEncShare, ct *CT1, commitments []*bn128.GT) bool {
	if share == nil || share.Proof == nil || share.Index < 1 || !equalGT(share.C2, ct.C2) || len(commitments) == 0 {
		return false
	}
	commitment := interpolateCommitment(commitments, share.Index)
	return verify(param, param.G1, commitment, ct.C1, share.C1, share.Proof)
}

// Combine rejects fewer than t valid shares and excludes malformed injected shares.
func Combine(param *Param, shares []*ReEncShare, ct *CT1, commitments []*bn128.GT, t int) (*CT2, error) {
	if t < 1 {
		return nil, errors.New("invalid threshold")
	}

	valid := make([]*ReEncShare, 0, len(shares))
	seen := make(map[int]bool)
	for _, share := range shares {
		if share != nil && !seen[share.Index] && VerifyShare(param, share, ct, commitments) {
			seen[share.Index] = true
			valid = append(valid, share)
		}
	}
	if len(valid) < t {
		return nil, errors.New("fewer than t valid ciphertext shares")
	}

	selected := valid[:t]
	combined := new(bn128.GT).ScalarBaseMult(big.NewInt(0))
	for i, share := range selected {
		coefficient, err := lagrangeAtZero(selected, i)
		if err != nil {
			return nil, err
		}
		term := new(bn128.GT).ScalarMult(share.C1, coefficient)
		combined.Add(combined, term)
	}
	return &CT2{C1: combined, C2: new(bn128.GT).Set(ct.C2)}, nil
}

// CombineCTPRE implements the CTPRE.Combine algorithm: it combines exactly t
// selected shares and deliberately performs no VCTPRE proof verification.
func CombineCTPRE(shares []*ReEncShare, t, n int) (*CT2, error) {
	if t < 1 || n < t || len(shares) < t {
		return nil, errors.New("fewer than t ciphertext shares")
	}

	selected := shares[:t]
	seen := make(map[int]bool, t)
	for _, share := range selected {
		if share == nil || share.Index < 1 || share.Index > n {
			return nil, errors.New("invalid ciphertext share index")
		}
		if seen[share.Index] {
			return nil, errors.New("duplicate ciphertext share index")
		}
		seen[share.Index] = true
		if !equalGT(share.C2, selected[0].C2) {
			return nil, errors.New("ciphertext share components do not match")
		}
	}

	combined := new(bn128.GT).ScalarBaseMult(big.NewInt(0))
	for i, share := range selected {
		coefficient, err := lagrangeAtZero(selected, i)
		if err != nil {
			return nil, err
		}
		combined.Add(combined, new(bn128.GT).ScalarMult(share.C1, coefficient))
	}
	return &CT2{C1: combined, C2: new(bn128.GT).Set(selected[0].C2)}, nil
}
func evaluate(coefficients []*big.Int, x int) *big.Int {
	result := new(big.Int)
	power := big.NewInt(1)
	xValue := big.NewInt(int64(x))
	for _, coefficient := range coefficients {
		term := new(big.Int).Mul(coefficient, power)
		result.Add(result, term)
		result.Mod(result, bn128.Order)
		power.Mul(power, xValue)
		power.Mod(power, bn128.Order)
	}
	return result
}

func interpolateCommitment(commitments []*bn128.GT, x int) *bn128.GT {
	result := new(bn128.GT).ScalarBaseMult(big.NewInt(0))
	power := big.NewInt(1)
	xValue := big.NewInt(int64(x))
	for _, commitment := range commitments {
		result.Add(result, new(bn128.GT).ScalarMult(commitment, power))
		power.Mul(power, xValue)
		power.Mod(power, bn128.Order)
	}
	return result
}

func lagrangeAtZero(shares []*ReEncShare, current int) (*big.Int, error) {
	xi := big.NewInt(int64(shares[current].Index))
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	for j, share := range shares {
		if j == current {
			continue
		}
		xj := big.NewInt(int64(share.Index))
		numerator.Mul(numerator, new(big.Int).Neg(xj))
		numerator.Mod(numerator, bn128.Order)
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, bn128.Order)
		denominator.Mul(denominator, diff)
		denominator.Mod(denominator, bn128.Order)
	}
	inv := new(big.Int).ModInverse(denominator, bn128.Order)
	if inv == nil {
		return nil, errors.New("duplicate share index")
	}
	coefficient := new(big.Int).Mul(numerator, inv)
	coefficient.Mod(coefficient, bn128.Order)
	return coefficient, nil
}

func prove(param *Param, h *bn128.G1, hBar *bn128.GT, g *bn128.G1, gBar *bn128.GT, witness *bn128.G2) *Proof {
	r := randomScalar()
	hHat := new(bn128.GT).ScalarMult(bn128.Pair(h, param.G2), r)
	gHat := new(bn128.GT).ScalarMult(bn128.Pair(g, param.G2), r)
	challenge := proofHash(h, hBar, g, gBar, hHat, gHat)
	rHat := new(bn128.G2).Add(new(bn128.G2).ScalarMult(param.G2, r), new(bn128.G2).ScalarMult(witness, challenge))
	return &Proof{HHat: hHat, GHat: gHat, RHat: rHat}
}

func verify(param *Param, h *bn128.G1, hBar *bn128.GT, g *bn128.G1, gBar *bn128.GT, proof *Proof) bool {
	if proof == nil || proof.HHat == nil || proof.GHat == nil || proof.RHat == nil {
		return false
	}
	challenge := proofHash(h, hBar, g, gBar, proof.HHat, proof.GHat)
	leftH := bn128.Pair(h, proof.RHat)
	rightH := new(bn128.GT).Add(proof.HHat, new(bn128.GT).ScalarMult(hBar, challenge))
	leftG := bn128.Pair(g, proof.RHat)
	rightG := new(bn128.GT).Add(proof.GHat, new(bn128.GT).ScalarMult(gBar, challenge))
	return equalGT(leftH, rightH) && equalGT(leftG, rightG)
}

func proofHash(h *bn128.G1, hBar *bn128.GT, g *bn128.G1, gBar *bn128.GT, hHat *bn128.GT, gHat *bn128.GT) *big.Int {
	hash := sha256.New()
	hash.Write(h.Marshal())
	hash.Write(hBar.Marshal())
	hash.Write(g.Marshal())
	hash.Write(gBar.Marshal())
	hash.Write(hHat.Marshal())
	hash.Write(gHat.Marshal())
	challenge := new(big.Int).SetBytes(hash.Sum(nil))
	return challenge.Mod(challenge, bn128.Order)
}

func equalGT(left, right *bn128.GT) bool {
	return left != nil && right != nil && bytes.Equal(left.Marshal(), right.Marshal())
}
