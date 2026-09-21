package vctpre

import (
	"fmt"
	"testing"
	"time"

	bn128 "pvpre/bn128"
)

func testMessage(_ *Param) *bn128.GT {
	return bn128.Pair(new(bn128.G1).ScalarBaseMult(randomScalar()), new(bn128.G2).ScalarBaseMult(randomScalar()))
}

func TestVCTPRE0(t *testing.T) {
	const n = 80
	const threshold = n/2 + 1
	param := Setup()
	skA, pkA := KeyGen(param)
	skB, pkB := KeyGen(param)
	message := testMessage(param)

	firstLevel := Enc1(param, pkA, message)
	if !equalGT(message, Dec1(param, skA, firstLevel)) {
		t.Fatal("first-level decryption failed")
	}

	controlKey := CKGen()

	// RKGen
	reEncryptionKeys, commitments, err := RKShare(param, skA, pkB, controlKey, threshold, n)
	if err != nil {
		t.Fatal(err)
	}

	numRuns := 30 //重复执行次数

	// =================== Test RKGen =======================
	var totalDuration1 time.Duration

	// 执行多次，计算平均时间
	startTime1 := time.Now()
	for i := 0; i < numRuns; i++ {
		_, _, _ = RKShare(param, skA, pkB, controlKey, threshold, n)
	}
	endTime1 := time.Now()
	totalDuration1 = endTime1.Sub(startTime1)

	// 计算平均时间
	averageDuration1 := totalDuration1 / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("n = %d: Average RKGen time over %d runs: %s\n", n, numRuns, averageDuration1)
	// =================== Test RKGen =======================

	authorized := CTAuth(param, firstLevel, pkA, controlKey)

	// ReEnc
	shares := make([]*ReEncShare, n)
	for i, key := range reEncryptionKeys {
		shares[i], err = ReEncryptShare(param, key, authorized, i+1)
		if err != nil {
			t.Fatal(err)
		}
	}

	// =================== Test ReEnc =======================

	var totalDuration2 time.Duration

	// 执行多次，计算平均时间
	startTime2 := time.Now()
	for i := 0; i < numRuns; i++ {
		for i, key := range reEncryptionKeys {
			_, err = ReEncryptShare(param, key, authorized, i+1)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	endTime2 := time.Now()
	totalDuration2 = endTime2.Sub(startTime2)

	// 计算平均时间
	averageDuration2 := totalDuration2 / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("n = %d: Average ReEnc time over %d runs: %s\n", n, numRuns, averageDuration2)

	// =================== Test ReEnc =======================

	// ReEncVerify
	for i := range shares {
		if !VerifyShare(param, shares[i], authorized, commitments) {
			t.Fatalf("valid share %d did not verify", i+1)
		}
	}

	// =================== Test ReEncVerify =======================
	var totalDuration3 time.Duration

	// 执行多次，计算平均时间
	startTime3 := time.Now()
	for i := 0; i < numRuns; i++ {
		for i := range shares {
			if !VerifyShare(param, shares[i], authorized, commitments) {
				t.Fatalf("valid share %d did not verify", i+1)
			}
		}
	}
	endTime3 := time.Now()
	totalDuration3 = endTime3.Sub(startTime3)

	// 计算平均时间
	averageDuration3 := totalDuration3 / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("n = %d: Average ReEncVerify time over %d runs: %s\n", n, numRuns, averageDuration3)
	// =================== Test ReEncVerify =======================

	// Combine + Dec2
	secondLevel, err := CombineCTPRE(shares, threshold, n)
	m := Dec2(param, skB, secondLevel)

	if !equalGT(message, m) {
		t.Fatal("threshold re-encryption decryption failed")
	}

	// =================== Test Combine + Dec2 =======================
	var totalDuration4 time.Duration

	// 执行多次，计算平均时间
	startTime4 := time.Now()
	for i := 0; i < numRuns; i++ {
		ct2, _ := CombineCTPRE(shares, threshold, n)
		_ = Dec2(param, skB, ct2)
	}
	endTime4 := time.Now()
	totalDuration4 = endTime4.Sub(startTime4)

	// 计算平均时间
	averageDuration4 := totalDuration4 / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("n = %d: Average Combine+Dec2 time over %d runs: %s\n", n, numRuns, averageDuration4)

}

// func TestVCTPRE(t *testing.T) {
// 	const threshold = 2
// 	const proxies = 4

// 	param := Setup()
// 	skA, pkA := KeyGen(param)
// 	skB, pkB := KeyGen(param)
// 	message := testMessage(param)

// 	firstLevel := Enc1(param, pkA, message)
// 	if !equalGT(message, Dec1(param, skA, firstLevel)) {
// 		t.Fatal("first-level decryption failed")
// 	}

// 	controlKey := CKGen()
// 	reEncryptionKeys, commitments, err := RKShare(param, skA, pkB, controlKey, threshold, proxies)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	authorized := CTAuth(param, firstLevel, pkA, controlKey)

// 	shares := make([]*ReEncShare, proxies)
// 	for i, key := range reEncryptionKeys {
// 		shares[i], err = ReEncryptShare(param, key, authorized, i+1)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		if !VerifyShare(param, shares[i], authorized, commitments) {
// 			t.Fatalf("valid share %d did not verify", i+1)
// 		}
// 	}

// 	secondLevel, err := Combine(param, shares[:threshold], authorized, commitments, threshold)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if !equalGT(message, Dec2(param, skB, secondLevel)) {
// 		t.Fatal("threshold re-encryption decryption failed")
// 	}

// 	// An injected share with an invalid proof is excluded while t honest shares remain.
// 	forged := *shares[0]
// 	forged.Proof = &Proof{HHat: shares[0].Proof.HHat, GHat: shares[0].Proof.GHat, RHat: param.G2}
// 	secondLevel, err = Combine(param, []*ReEncShare{&forged, shares[1], shares[2]}, authorized, commitments, threshold)
// 	if err != nil {
// 		t.Fatalf("invalid share should be excluded: %v", err)
// 	}
// 	if !equalGT(message, Dec2(param, skB, secondLevel)) {
// 		t.Fatal("combining valid shares after injection failed")
// 	}
// }

// func TestVCTPRERejectsFewerThanTValidShares(t *testing.T) {
// 	param := Setup()
// 	skA, pkA := KeyGen(param)
// 	_, pkB := KeyGen(param)
// 	message := testMessage(param)
// 	controlKey := CKGen()
// 	keys, commitments, err := RKShare(param, skA, pkB, controlKey, 2, 3)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	authorized := CTAuth(param, Enc1(param, pkA, message), pkA, controlKey)
// 	share, err := ReEncryptShare(param, keys[0], authorized, 1)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if _, err = Combine(param, []*ReEncShare{share}, authorized, commitments, 2); err == nil {
// 		t.Fatal("Combine accepted fewer than t valid shares")
// 	}
// }
