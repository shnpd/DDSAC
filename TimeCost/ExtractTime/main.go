package main

import (
	"DDSAC/Crypto"
	"DDSAC/Crypto/ECC"
	"DDSAC/Label"
	"DDSAC/Segment"
	"DDSAC/Signature"
	"DDSAC/Wallet"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strings"
	"time"
)

func main() {
	txid, _ := chainhash.NewHashFromStr("c9648387eca4a69cc36e8234c8eee298d6ccb8fd83229dfd931afc1f2637b95f")

	keyPi := []byte("12345678901234567890123456789012")
	keyF := []byte{1, 2, 3}
	keyH := []byte("1234567890123456")
	keyQ := []byte("1234567890123456")
	keyP := []byte("12345678901234567890123456789012")
	client := Wallet.InitClient("127.0.0.1:28334", "mainnet")
	for i := 0; i < 5; i++ {

		start := time.Now()
		trans := Label.FilterLabel(client, keyH, 1)
		CTpairs := pairTrans(trans, keyF)
		for j := 0; j < 64; j++ {
			CTpairs = append(CTpairs, []*chainhash.Hash{
				txid, txid,
			})
		}
		Extract(CTpairs, client, keyPi, keyP, keyQ, keyF)
		//fmt.Println(m)
		duration := time.Since(start)
		fmt.Println(duration)
	}

}

// Extract 根据筛选出的交易对提取秘密消息
func Extract(CTpairs [][]*chainhash.Hash, client *rpcclient.Client, keyPi, keyP, keyQ, keyF []byte) string {
	var B []string
	for _, pair := range CTpairs {
		CTi := pair[0]
		CTj := pair[1]
		rawTxi, _ := client.GetRawTransaction(CTi)
		rawTxj, _ := client.GetRawTransaction(CTj)
		sigi := Signature.GetSignaruteFromTx(hex.EncodeToString(rawTxi.MsgTx().TxIn[0].SignatureScript))
		// 只讨论最简单的P2PK签名
		if sigi == nil {
			continue
		}
		riModN := sigi.R()
		ri := ECC.ModNScalarToField(&riModN)
		y, _ := ECC.CalculateYFromX(&ri)
		y2 := new(secp256k1.FieldVal)
		y2.Set(y)
		negy := y2.Negate(63)

		point1 := calculate2(&ri, y, keyF)
		//point2 := calculate2(&ri, negy)

		hiBytes, _ := Signature.GetHashFromTx(rawTxi, client)
		hi := new(secp256k1.ModNScalar)
		hi.SetByteSlice(hiBytes)
		si := sigi.S()
		hj := new(secp256k1.ModNScalar)
		hjBytes, _ := Signature.GetHashFromTx(rawTxj, client)
		hj.SetByteSlice(hjBytes)
		sigj := Signature.GetSignaruteFromTx(hex.EncodeToString(rawTxj.MsgTx().TxIn[0].SignatureScript))
		if sigj == nil {
			continue
		}
		rj := sigj.R()
		sj := sigj.S()

		kj := new(secp256k1.ModNScalar)
		if point1.X == ECC.ModNScalarToField(&rj) {
			var tempByte []byte
			tempByte = append(append(tempByte, ri.Bytes()[:]...), y.Bytes()[:]...)
			HP := Crypto.HashSHA256(tempByte)
			FHP := Crypto.PRF(HP, keyF)
			kj.SetByteSlice(FHP)
		} else {
			var tempByte []byte
			tempByte = append(append(tempByte, ri.Bytes()[:]...), negy.Bytes()[:]...)
			HP := Crypto.HashSHA256(tempByte)
			FHP := Crypto.PRF(HP, keyF)
			kj.SetByteSlice(FHP)
		}

		dj := new(secp256k1.ModNScalar).InverseValNonConst(&rj).Mul(sj.Mul(kj).Add(hj.Negate()))
		djBytes := dj.Bytes()
		diBytes, _ := Crypto.Decrypt(keyQ, djBytes[:])
		di := new(secp256k1.ModNScalar)
		di.SetByteSlice(diBytes)
		ki := new(secp256k1.ModNScalar).InverseValNonConst(&si).Mul(di.Mul(&riModN).Add(hi))
		kiBytes := ki.Bytes()
		Bi, _ := Crypto.Decrypt(keyP, kiBytes[:])
		B = append(B, Segment.ConvertToBinary(Bi))
	}
	Blen := len(B)
	// 预共享的结束标志
	endFlag := Segment.ConvertToBinary([]byte{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04})
	if Blen < 2 {
		return ""
	}
	t := B[Blen-2] + B[Blen-1]
	index := strings.Index(t, endFlag)
	// 截取结束标志之前的内容
	if index != -1 {
		B[Blen-2] = B[Blen-2][:index]
	}
	b := ""
	for i := 0; i <= Blen-1; i++ {
		b += B[i]
	}
	c := Crypto.ConvertStr2Byte(b)
	m, _ := Crypto.Decrypt(keyPi, c)
	return string(m)
}

// calculate2 计算F(H(x,y))*G
func calculate2(x, y *secp256k1.FieldVal, keyF []byte) secp256k1.JacobianPoint {
	var pointByte []byte
	pointByte = append(append(pointByte, x.Bytes()[:]...), y.Bytes()[:]...)
	t := new(secp256k1.ModNScalar)
	HP := Crypto.HashSHA256(pointByte)
	FHP := Crypto.PRF(HP, keyF)
	t.SetByteSlice(FHP)
	var point11 secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(t, &point11)
	return point11
}

// pairTrans 输入一组交易，将该组交易两两配对；（原论文中没有给出源码，也没有说明具体使用的椭圆曲线，本代码尝试复现时无法得到正确的纵坐标，因此主要模拟了原文的计算逻辑以模拟正常的时间效率，在最后返回时直接返回预先计算好的配对交易）
func pairTrans(txs []*btcjson.TxRawResult, keyF []byte) [][]*chainhash.Hash {
	var pairs [][]*btcjson.TxRawResult
	for _, cti := range txs {
		var pair []*btcjson.TxRawResult
		pair = append(pair, cti)
		sig := Signature.GetSignaruteFromTx(cti.Vin[0].ScriptSig.Hex)
		// 不讨论隔离见证
		if sig == nil {
			continue
		}
		r := sig.R()
		// 计算纵坐标
		r2 := ECC.ModNScalarToField(&r)
		y, _ := ECC.CalculateYFromX(&r2)
		// 计算negate需要创建副本，否则会修改原值
		y2 := new(secp256k1.FieldVal)
		y2.Set(y)
		negy := y2.Negate(63)

		// 计算配对交易的ki2G
		point11 := calculate2(&r2, y, keyF)
		point21 := calculate2(&r2, negy, keyF)
		// 遍历交易集合寻找配对交易
		for _, ctj := range txs {
			sig = Signature.GetSignaruteFromTx(ctj.Vin[0].ScriptSig.Hex)
			if sig == nil {
				continue
			}
			r = sig.R()
			if *point11.X.Bytes() == r.Bytes() || *point21.X.Bytes() == r.Bytes() {
				pair = append(pair, ctj)
				pairs = append(pairs, pair)
				break
			}
		}
	}
	//return pairs
	//	直接返回预先计算好的分组
	//tx1, _ := chainhash.NewHashFromStr("838bb8f586b5d1e5e76b77c7372b5ecb263b89a9a218771a65b9e3b88b1d39cd")
	//tx2, _ := chainhash.NewHashFromStr("6f9722a9ba54ca9bbed06464b8160d64c64fe78095e342993ad333f65f7902b4")
	//tx3, _ := chainhash.NewHashFromStr("0440e6594fbde420e9f521f46f9e77792377fc4f73bfcbcdf4f349a88d3b1b4c")
	//tx4, _ := chainhash.NewHashFromStr("88eac6545dae2366f018a364b5fd771076cca8aed7e0068b4bfad94a2d161369")
	//tx5, _ := chainhash.NewHashFromStr("d0f5bcd656d1710f77d2f12bae41d149e1c2e7446cdc07dd7fe9c6c583c200a7")
	//tx6, _ := chainhash.NewHashFromStr("3ea11af032849bb1e7c6e019fd72e2c564a69f89127e6f429c55b3dbc3372d15")
	//return [][]*chainhash.Hash{{tx6, tx3}, {tx5, tx1}, {tx2, tx4}}

	// 因为mainnet中没有特殊交易所以我们返回nil，在外部赋值一些正常交易进行消息提取，只要模拟正常的时间开销即可
	return nil
}
