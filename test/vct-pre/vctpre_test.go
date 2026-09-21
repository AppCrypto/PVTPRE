package vctpre

import (
	"testing"

	bn128 "pvpre/bn128"
)

func testMessage(_ *Param) *bn128.GT {
	return bn128.Pair(new(bn128.G1).ScalarBaseMult(randomScalar()), new(bn128.G2).ScalarBaseMult(randomScalar()))
}

func TestVCTPRE(t *testing.T) {
	const threshold = 2
	const proxies = 4

	param := Setup()
	skA, pkA := KeyGen(param)
	skB, pkB := KeyGen(param)
	message := testMessage(param)

	firstLevel := Enc1(param, pkA, message)
	if !equalGT(message, Dec1(param, skA, firstLevel)) {
		t.Fatal("first-level decryption failed")
	}

	controlKey := CKGen()
	reEncryptionKeys, commitments, err := RKShare(param, skA, pkB, controlKey, threshold, proxies)
	if err != nil {
		t.Fatal(err)
	}
	authorized := CTAuth(param, firstLevel, pkA, controlKey)

	shares := make([]*ReEncShare, proxies)
	for i, key := range reEncryptionKeys {
		shares[i], err = ReEncryptShare(param, key, authorized, i+1)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyShare(param, shares[i], authorized, commitments) {
			t.Fatalf("valid share %d did not verify", i+1)
		}
	}

	secondLevel, err := Combine(param, shares[:threshold], authorized, commitments, threshold)
	if err != nil {
		t.Fatal(err)
	}
	if !equalGT(message, Dec2(param, skB, secondLevel)) {
		t.Fatal("threshold re-encryption decryption failed")
	}

	// An injected share with an invalid proof is excluded while t honest shares remain.
	forged := *shares[0]
	forged.Proof = &Proof{HHat: shares[0].Proof.HHat, GHat: shares[0].Proof.GHat, RHat: param.G2}
	secondLevel, err = Combine(param, []*ReEncShare{&forged, shares[1], shares[2]}, authorized, commitments, threshold)
	if err != nil {
		t.Fatalf("invalid share should be excluded: %v", err)
	}
	if !equalGT(message, Dec2(param, skB, secondLevel)) {
		t.Fatal("combining valid shares after injection failed")
	}
}

func TestVCTPRERejectsFewerThanTValidShares(t *testing.T) {
	param := Setup()
	skA, pkA := KeyGen(param)
	_, pkB := KeyGen(param)
	message := testMessage(param)
	controlKey := CKGen()
	keys, commitments, err := RKShare(param, skA, pkB, controlKey, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	authorized := CTAuth(param, Enc1(param, pkA, message), pkA, controlKey)
	share, err := ReEncryptShare(param, keys[0], authorized, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Combine(param, []*ReEncShare{share}, authorized, commitments, 2); err == nil {
		t.Fatal("Combine accepted fewer than t valid shares")
	}
}
