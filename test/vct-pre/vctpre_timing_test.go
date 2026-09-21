package vctpre

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestVCTPRETiming prints average timings in microseconds for the requested
// network sizes. Run with: go test ./test/vct-pre -run TestVCTPRETiming -v.
func TestVCTPRETiming(t *testing.T) {
	iterations := 3
	if value := os.Getenv("VCTPRE_TIMING_ITERATIONS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("VCTPRE_TIMING_ITERATIONS must be positive: %q", value)
		}
		iterations = parsed
	}

	networkSizes := []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	if value := os.Getenv("VCTPRE_TIMING_N"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			t.Fatalf("VCTPRE_TIMING_N must be positive: %q", value)
		}
		networkSizes = []int{n}
	}

	fmt.Println("n,t,RKGen_us,ReEnc_us,REncVerify_us,REncVerifyAll_us,Dec1_us,Combine_us")
	for _, n := range networkSizes {
		threshold := (n - 1) / 3
		if threshold < 1 {
			threshold = 1
		}
		param := Setup()
		skA, pkA := KeyGen(param)
		skB, pkB := KeyGen(param)
		message := testMessage(param)
		controlKey := CKGen()
		firstLevel := Enc1(param, pkA, message)
		authorized := CTAuth(param, firstLevel, pkA, controlKey)

		reEncryptionKeys, commitments, err := RKShare(param, skA, pkB, controlKey, threshold, n)
		if err != nil {
			t.Fatal(err)
		}
		shares := make([]*ReEncShare, n)
		for i, key := range reEncryptionKeys {
			shares[i], err = ReEncryptShare(param, key, authorized, i+1)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !VerifyShare(param, shares[n-1], authorized, commitments) {
			t.Fatalf("n=%d: setup share did not verify", n)
		}

		rkGen := averageDuration(iterations, func() {
			if _, _, err := RKShare(param, skA, pkB, controlKey, threshold, n); err != nil {
				panic(err)
			}
		})
		reEnc := averageDuration(iterations, func() {
			if _, err := ReEncryptShare(param, reEncryptionKeys[n-1], authorized, n); err != nil {
				panic(err)
			}
		})
		verify := averageDuration(iterations, func() {
			if !VerifyShare(param, shares[n-1], authorized, commitments) {
				panic("valid share did not verify")
			}
		})
		verifyAll := averageDuration(iterations, func() {
			for _, share := range shares {
				if !VerifyShare(param, share, authorized, commitments) {
					panic("valid share did not verify")
				}
			}
		})
		dec1 := averageDuration(iterations, func() {
			_ = Dec1(param, skA, firstLevel)
		})
		combine := averageDuration(iterations, func() {
			secondLevel, err := Combine(param, shares, authorized, commitments, threshold)
			if err != nil {
				panic(err)
			}
			if !equalGT(message, Dec2(param, skB, secondLevel)) {
				panic("combined ciphertext did not decrypt")
			}
		})

		fmt.Printf("%d,%d,%d,%d,%d,%d,%d,%d\n", n, threshold, rkGen.Microseconds(), reEnc.Microseconds(), verify.Microseconds(), verifyAll.Microseconds(), dec1.Microseconds(), combine.Microseconds())
	}
}

func averageDuration(iterations int, operation func()) time.Duration {
	start := time.Now()
	for i := 0; i < iterations; i++ {
		operation()
	}
	return time.Since(start) / time.Duration(iterations)
}

// TestDelegatorEnc1Timing measures one delegator first-level encryption.
func TestDelegatorEnc1Timing(t *testing.T) {
	const iterations = 100

	param := Setup()
	_, pkA := KeyGen(param)
	message := testMessage(param)
	duration := averageDuration(iterations, func() {
		_ = Enc1(param, pkA, message)
	})
	fmt.Printf("DelegatorEnc1_us,%d\n", duration.Microseconds())
}

// TestVCTPRESingleNodeTiming measures the explicit (t, n) = (1, 1) case.
func TestVCTPRESingleNodeTiming(t *testing.T) {
	const iterations = 20
	const threshold = 1
	const proxies = 1

	param := Setup()
	skA, pkA := KeyGen(param)
	skB, pkB := KeyGen(param)
	message := testMessage(param)
	controlKey := CKGen()
	firstLevel := Enc1(param, pkA, message)
	authorized := CTAuth(param, firstLevel, pkA, controlKey)
	reEncryptionKeys, commitments, err := RKShare(param, skA, pkB, controlKey, threshold, proxies)
	if err != nil {
		t.Fatal(err)
	}
	share, err := ReEncryptShare(param, reEncryptionKeys[0], authorized, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyShare(param, share, authorized, commitments) {
		t.Fatal("single-node share did not verify")
	}
	secondLevel, err := Combine(param, []*ReEncShare{share}, authorized, commitments, threshold)
	if err != nil || !equalGT(message, Dec2(param, skB, secondLevel)) {
		t.Fatal("single-node combination did not decrypt")
	}

	rkGen := averageDuration(iterations, func() {
		if _, _, err := RKShare(param, skA, pkB, controlKey, threshold, proxies); err != nil {
			panic(err)
		}
	})
	reEnc := averageDuration(iterations, func() {
		if _, err := ReEncryptShare(param, reEncryptionKeys[0], authorized, 1); err != nil {
			panic(err)
		}
	})
	verify := averageDuration(iterations, func() {
		if !VerifyShare(param, share, authorized, commitments) {
			panic("valid single-node share did not verify")
		}
	})
	verifyAll := averageDuration(iterations, func() {
		if !VerifyShare(param, share, authorized, commitments) {
			panic("valid single-node share did not verify")
		}
	})
	dec1 := averageDuration(iterations, func() {
		_ = Dec1(param, skA, firstLevel)
	})
	combine := averageDuration(iterations, func() {
		if _, err := Combine(param, []*ReEncShare{share}, authorized, commitments, threshold); err != nil {
			panic(err)
		}
	})

	fmt.Printf("n,t,RKGen_us,ReEnc_us,REncVerify_us,REncVerifyAll_us,Dec1_us,Combine_us\n")
	fmt.Printf("1,1,%d,%d,%d,%d,%d,%d\n", rkGen.Microseconds(), reEnc.Microseconds(), verify.Microseconds(), verifyAll.Microseconds(), dec1.Microseconds(), combine.Microseconds())
}

// TestVCTPREVerifyTTiming measures verification of the t shares needed for threshold recovery.
func TestVCTPREVerifyTTiming(t *testing.T) {
	iterations := 3
	if value := os.Getenv("VCTPRE_TIMING_ITERATIONS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("VCTPRE_TIMING_ITERATIONS must be positive: %q", value)
		}
		iterations = parsed
	}

	n := 100
	if value := os.Getenv("VCTPRE_TIMING_N"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("VCTPRE_TIMING_N must be positive: %q", value)
		}
		n = parsed
	}
	threshold := (n - 1) / 3
	if threshold < 1 {
		threshold = 1
	}

	param := Setup()
	skA, pkA := KeyGen(param)
	_, pkB := KeyGen(param)
	message := testMessage(param)
	controlKey := CKGen()
	authorized := CTAuth(param, Enc1(param, pkA, message), pkA, controlKey)
	reEncryptionKeys, commitments, err := RKShare(param, skA, pkB, controlKey, threshold, n)
	if err != nil {
		t.Fatal(err)
	}
	shares := make([]*ReEncShare, n)
	for i, key := range reEncryptionKeys {
		shares[i], err = ReEncryptShare(param, key, authorized, i+1)
		if err != nil {
			t.Fatal(err)
		}
	}

	verifyT := averageDuration(iterations, func() {
		for _, share := range shares[:threshold] {
			if !VerifyShare(param, share, authorized, commitments) {
				panic("valid share did not verify")
			}
		}
	})
	fmt.Printf("n,t,REncVerifyT_us\n%d,%d,%d\n", n, threshold, verifyT.Microseconds())
}

// TestCTPRECombineDec1Timing measures the two CTPRE algorithms shown in Fig. 2.
func TestCTPRECombineDec1Timing(t *testing.T) {
	iterations := 3
	if value := os.Getenv("VCTPRE_TIMING_ITERATIONS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("VCTPRE_TIMING_ITERATIONS must be positive: %q", value)
		}
		iterations = parsed
	}

	n := 100
	if value := os.Getenv("VCTPRE_TIMING_N"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("VCTPRE_TIMING_N must be positive: %q", value)
		}
		n = parsed
	}
	threshold := (n - 1) / 3
	if threshold < 1 {
		threshold = 1
	}

	param := Setup()
	skA, pkA := KeyGen(param)
	skB, pkB := KeyGen(param)
	message := testMessage(param)
	controlKey := CKGen()
	firstLevel := Enc1(param, pkA, message)
	authorized := CTAuth(param, firstLevel, pkA, controlKey)
	reEncryptionKeys, _, err := RKShare(param, skA, pkB, controlKey, threshold, n)
	if err != nil {
		t.Fatal(err)
	}
	shares := make([]*ReEncShare, n)
	for i, key := range reEncryptionKeys {
		shares[i], err = ReEncryptShare(param, key, authorized, i+1)
		if err != nil {
			t.Fatal(err)
		}
	}
	secondLevel, err := CombineCTPRE(shares[:threshold], threshold, n)
	if err != nil || !equalGT(message, Dec2(param, skB, secondLevel)) {
		t.Fatal("CTPRE.Combine did not produce a decryptable ciphertext")
	}

	combine := averageDuration(iterations, func() {
		if _, err := CombineCTPRE(shares[:threshold], threshold, n); err != nil {
			panic(err)
		}
	})
	dec1 := averageDuration(iterations, func() {
		_ = Dec1(param, skA, firstLevel)
	})
	fmt.Printf("n,t,CTPRECombine_us,CTPREDec1_us\n%d,%d,%d,%d\n", n, threshold, combine.Microseconds(), dec1.Microseconds())
}
