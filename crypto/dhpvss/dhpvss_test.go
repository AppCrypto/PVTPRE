package dhpvss_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"pvpre/crypto/dhpvss"
	"testing"

	bn128 "github.com/fentec-project/bn256"
	"github.com/stretchr/testify/assert"
)

func TestHfun(t *testing.T) {
	//实例输入
	input := []byte("test")
	nValue := 15
	tValue := 11 // 示例的阈值

	coefficients := dhpvss.Hfunc(input, nValue, tValue)

	// 检查返回的系数数量是否为t-1
	assert.Len(t, coefficients, tValue-1, "Hfunc should return t-1 coefficients")

	// 确保系数是大整数类型
	for _, coeff := range coefficients {
		assert.IsType(t, &big.Int{}, coeff, "Coefficients should be of type *big.Int")
	}
}

func TestComputeVI(t *testing.T) {
	alpha := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}
	p := big.NewInt(11) //实例质数p

	vi := dhpvss.ComputeVI(alpha, p)

	//结果应该是与alpha长度一样
	assert.Len(t, vi, len(alpha), "ComputeVI should return the same number of v_i as alpha")

	// 检查 vi 中的每一个元素是否为 *big.Int 类型
	for _, v := range vi {
		assert.IsType(t, &big.Int{}, v, "Each v_i should be of type *big.Int")
	}
}

func TestDHPVSSSetup(t *testing.T) {
	n, threshold, l := 10, 6, 128 // 示例参数

	Par, s, err := dhpvss.DHPVSSSetup(n, threshold, l)
	assert.NoError(t, err, "DHPVSSSetup should not return an error")
	assert.NotNil(t, Par, "DHPVSSSetup should return a non-nil Dhpvsspar object")
	assert.NotNil(t, s, "DHPVSSSetup should return a secret key")

	// 检查返回的公共参数是否有效
	assert.Len(t, Par.Vi, n, "DHPVSSSetup's Vi should have the same number of elements as n")
}

func TestDHPVSSShare(t *testing.T) {
	// 使用随机生成的公共密钥、私钥和其他参数进行测试
	Par, s, err := dhpvss.DHPVSSSetup(10, 6, 128)
	assert.NoError(t, err)

	// 2. 生成参与方的密钥对
	ska := big.NewInt(7)
	skb := big.NewInt(10)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, 10)
	SKs := make([]*big.Int, 10)
	for i := 0; i < Par.PP.N; i++ {
		SKs[i], err = rand.Int(rand.Reader, Par.PP.P)
		if err != nil {
			fmt.Println("Error generating random value for SKs:", err)
			return
		}
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}

	C, pi_sh := dhpvss.DHPVSSShare(Par, pkb, pka, ska, PKs, s)

	assert.Len(t, C, len(PKs), "DHPVSSShare should return a slice of C with the same length as PKs")
	assert.NotNil(t, pi_sh, "DHPVSSShare should return a non-nil proof")
	assert.NotNil(t, pi_sh.C, "DLEQ proof C should not be nil")
}

func TestDHPVSSVerify(t *testing.T) {
	// 使用随机生成的公共密钥、私钥和其他参数进行测试
	Par, s, err := dhpvss.DHPVSSSetup(10, 6, 128)
	assert.NoError(t, err)

	// 2. 生成参与方的密钥对
	ska := big.NewInt(7)
	skb := big.NewInt(10)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, Par.PP.N)
	SKs := make([]*big.Int, Par.PP.N)
	for i := 0; i < Par.PP.N; i++ {
		SKs[i], err = rand.Int(rand.Reader, Par.PP.P)
		if err != nil {
			fmt.Println("Error generating random value for SKs:", err)
			return
		}
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}

	C, pi_sh := dhpvss.DHPVSSShare(Par, pkb, pka, ska, PKs, s)

	// 使用生成的 DLEQProof 进行验证
	valid := dhpvss.DHPVSSVerify(Par, pka, pkb, C, PKs, pi_sh)

	assert.True(t, valid, "DHPVSSVerify should return true for valid proof")
}

func TestDHPVSSPreRecon(t *testing.T) {
	// 使用随机生成的公共密钥、私钥和其他参数进行测试
	Par, s, err := dhpvss.DHPVSSSetup(5, 3, 128)
	assert.NoError(t, err)

	// 2. 生成参与方的密钥对
	ska := big.NewInt(7)
	skb := big.NewInt(10)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, 5)
	SKs := make([]*big.Int, 5)
	for i := 0; i < 5; i++ {
		SKs[i], err = rand.Int(rand.Reader, Par.PP.P)
		if err != nil {
			fmt.Println("Error generating random value for SKs:", err)
			return
		}
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}

	C, pi_sh := dhpvss.DHPVSSShare(Par, pkb, pka, ska, PKs, s)

	// 使用生成的 DLEQProof 进行验证
	valid := dhpvss.DHPVSSVerify(Par, pka, pkb, C, PKs, pi_sh)

	assert.True(t, valid, "DHPVSSVerify should return true for valid proof")

	Cp, pi_re := dhpvss.DHPVSSPreRecon(Par, pka, PKs, SKs, C)

	assert.NotNil(t, Cp, "Cp should not be nil")
	assert.NotNil(t, pi_re, "DLEQ proofs should not be nil")

	// 如果需要，你还可以验证生成的 DLEQ 证明的内容，例如检查 C, Z 等字段
	assert.Len(t, pi_re.C, len(C), "The length of pi_re.C should match the length of C")
	assert.Len(t, pi_re.Z, len(C), "The length of pi_re.Z should match the length of C")
}

func TestDHPVSSVerifyDec(t *testing.T) {
	// 使用随机生成的公共密钥、私钥和其他参数进行测试
	Par, s, err := dhpvss.DHPVSSSetup(10, 5, 128)
	assert.NoError(t, err)

	// 2. 生成参与方的密钥对
	ska := big.NewInt(7)
	skb := big.NewInt(10)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, Par.PP.N)
	SKs := make([]*big.Int, Par.PP.N)
	for i := 0; i < Par.PP.N; i++ {
		SKs[i], err = rand.Int(rand.Reader, Par.PP.P)
		if err != nil {
			fmt.Println("Error generating random value for SKs:", err)
			return
		}
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}

	C, pi_sh := dhpvss.DHPVSSShare(Par, pkb, pka, ska, PKs, s)

	// 使用生成的 DLEQProof 进行验证
	valid := dhpvss.DHPVSSVerify(Par, pka, pkb, C, PKs, pi_sh)

	assert.True(t, valid, "DHPVSSVerify should return true for valid proof")

	Cp, pi_re := dhpvss.DHPVSSPreRecon(Par, pka, PKs, SKs, C)

	result := dhpvss.DHPVSSVerifyDec(Par, pka, PKs, C, Cp, pi_re)

	assert.True(t, result, "Proof verification should pass")
}

func TestDHPVSS(t *testing.T) {
	// 测试设置
	n := 10        // 参与方数
	threshold := 6 // 阈值
	l := 256       // 密钥长度（位）

	// 1. 生成系统参数
	Par, s, err := dhpvss.DHPVSSSetup(n, threshold, l)
	if err != nil {
		t.Fatalf("Error setting up DHPVSS: %v", err)
	}
	fmt.Println("System Parameters Generated")

	// 2. 生成参与方的密钥对
	ska := big.NewInt(7)
	skb := big.NewInt(10)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, Par.PP.N)
	SKs := make([]*big.Int, Par.PP.N)
	for i := 0; i < Par.PP.N; i++ {
		SKs[i], err = rand.Int(rand.Reader, Par.PP.P)
		if err != nil {
			fmt.Println("Error generating random value for SKs:", err)
			return
		}
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}
	// 3. 分配秘密份额
	C, pi_sh := dhpvss.DHPVSSShare(Par, pkb, pka, ska, PKs, s)

	// 4. 验证份额
	isValid := dhpvss.DHPVSSVerify(Par, pka, pkb, C, PKs, pi_sh)
	if !isValid {
		t.Fatalf("Share validation failed")
	}
	fmt.Println("Share validation passed")

	// 5. 预重建过程验证
	Cp, pi_re := dhpvss.DHPVSSPreRecon(Par, pka, PKs, SKs, C)

	if Cp == nil || pi_re == nil {
		t.Fatalf("Failed to pre-reconstruct shares or proof")
	}

	// 6. 验证预重建的证明
	isValidReconstruct := dhpvss.DHPVSSVerifyDec(Par, pka, PKs, C, Cp, pi_re)
	if !isValidReconstruct {
		t.Fatalf("Pre-reconstruction verification failed")
	}
	fmt.Println("Pre-reconstruction verification passed.")

	// 7. 重建秘密
	// 取0前t个份额进行恢复
	I := make([]int, Par.PP.T)
	for i := 0; i < Par.PP.T; i++ {
		I[i] = i
	}
	S := dhpvss.DHPVSSRecon(Par, Cp, pka, skb, I) //假设I = [0,1,2]
	if S == nil {
		t.Fatalf("Failed to reconstruct secret")
	}

	// 重建结果应该和原始秘密一致
	expectedSecret := new(bn128.G1).ScalarBaseMult(s)
	if S.String() != expectedSecret.String() {
		t.Fatal("Recovered secret does not match the original secret")
	}
	fmt.Println("Secret reconstruction passed.")
}
