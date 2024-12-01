package main

import (
	"DDSAC/Crypto"
	"DDSAC/Key"
	"DDSAC/Label"
	"DDSAC/Segment"
	"DDSAC/Transaction"
	"DDSAC/Wallet"
	"fmt"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strconv"
)

var (
	keyPi = []byte("12345678901234567890123456789012")
	keyF  = []byte{1, 2, 3}
	keyH  = []byte("1234567890123456")
	keyQ  = []byte("1234567890123456")

	keyP       = []byte("12345678901234567890123456789012")
	client     *rpcclient.Client
	miningAddr = "SYZPAZEjXy7S4jbsUHqWUgv2FYomsR3RVS"
)

func main() {
	client = Wallet.InitClient("127.0.0.1:28335", "simnet")
	// 32byte 密钥对应256bit-AES
	message := []byte("1234567890123")
	// Encrypt the message
	ciphertext, _ := Crypto.Encrypt(keyPi, message)
	// 对密文进行分组
	B := Segment.Segment(ciphertext)

	//	将分组密文加密作为嵌入随机数（加密操作保证密文的随机性）

	// efs：随机因子集合
	var efs [][]string
	for _, v := range B {
		var t []string
		vByte := Crypto.ConvertStr2Byte(v)
		k1 := Crypto.PRP(vByte, keyP)
		k2 := computeK2(k1, keyF)
		t = append(t, string(k1))
		t = append(t, string(k2))
		efs = append(efs, t)
	}
	// afs：输出地址集合
	var afs []string
	addresses, _ := client.GetAddressesByAccount("default")
	for _, v := range addresses {
		afs = append(afs, v.String())
	}

	// lfs：标签集合
	lfs := Label.GenerateLabel(client, afs, keyH, 10)
	// 生成源地址对
	sourceAddrPair := generateSourceAddrPair(len(efs))
	// 生成一个区块将预备交易上链
	client.Generate(1)
	// 构造并发送特殊交易
	tx, err := buildTx(efs, lfs, afs, keyQ, sourceAddrPair)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tx)
}

// generateSourceAddrPair 生成num个地址对，并向每个地址都转入一笔UTXO用来发送特殊交易
func generateSourceAddrPair(num int) [][]string {
	var sourceAddrPair [][]string
	for i := 0; i < num; i++ {
		addresses := generatePrikPair([]byte(strconv.Itoa(i)), keyQ, client)
		// 从挖矿地址向源地址转入1笔utxo以便源地址发送交易
		Transaction.EntireSendTrans(miningAddr, addresses[0], 50*1e8, nil)
		Transaction.EntireSendTrans(miningAddr, addresses[1], 50*1e8, nil)
		sourceAddrPair = append(sourceAddrPair, addresses)
	}
	return sourceAddrPair
}

// buildTx 根据预先计算的辅助信息发送N对交易
func buildTx(efs [][]string, lfs []int64, afs []string, keyQ []byte, sourceAddrPair [][]string) ([][]string, error) {
	var txid [][]string
	N := len(efs)
	for i := 0; i < N; i++ {
		txpair := make([]string, 2)

		ki1 := []byte(efs[i][0])
		ki2 := []byte(efs[i][1])

		amounti1 := lfs[2*i]
		amounti2 := lfs[2*i+1]

		outaddri1 := afs[2*i]
		outaddri2 := afs[2*i+1]

		txId1, err := Transaction.EntireSendTrans(sourceAddrPair[i][0], outaddri1, amounti1, &ki1)
		if err != nil {
			return nil, err
		}
		txId2, err := Transaction.EntireSendTrans(sourceAddrPair[i][1], outaddri2, amounti2, &ki2)
		if err != nil {
			return nil, err
		}
		txpair[0] = txId1
		txpair[1] = txId2
		txid = append(txid, txpair)
	}
	return txid, nil
}

// generatePrikPair 生成一对私钥，返回私钥对应的地址
func generatePrikPair(seed, keyQ []byte, client *rpcclient.Client) []string {
	di1 := Crypto.HashSHA256(seed)
	di2, _ := Crypto.Encrypt(keyQ, di1)
	di2 = Crypto.HashSHA256(di2)

	Key.ImportPrivkey(di1, client)
	Key.ImportPrivkey(di2, client)

	addr1, _ := Key.GetAddressByPrivKey(di1)
	addr2, _ := Key.GetAddressByPrivKey(di2)

	return []string{addr1, addr2}
}

// computeK2 根据k1计算k2 k2=Fkf(h(k1G))
func computeK2(k1 []byte, keyF []byte) []byte {
	k := new(secp256k1.ModNScalar)
	k.SetByteSlice(k1)
	// 计算KG
	var k1G secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &k1G)
	k1G.ToAffine()
	//计算h(KG)
	var kGByte []byte
	kGByte = append(append(kGByte, k1G.X.Bytes()[:]...), k1G.Y.Bytes()[:]...)
	hKG := Crypto.HashSHA256(kGByte)
	//计算F(h(KG));F是伪随机函数，使用hmac-sha256实现
	k2 := Crypto.PRF(hKG, keyF)
	return k2
}
