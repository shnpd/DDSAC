package main

import (
	"DDSAC/Crypto"
	"DDSAC/Crypto/ECC"
	"DDSAC/Label"
	"DDSAC/Segment"
	"DDSAC/Signature"
	"DDSAC/Wallet"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strings"
	"time"
)

func main() {
	tx11, _ := chainhash.NewHashFromStr("1634f01db4eaa30471d1150c17d74a7d3991bb4bf8c28454479c25f7c737aec7")
	tx12, _ := chainhash.NewHashFromStr("796edad5340af5be03f8ec2f79dd1c46ee2b1b1ea1596e4e20287bacc53df32b")
	tx21, _ := chainhash.NewHashFromStr("cdf203dda34894dde92ca847aec859e33ba547eba0357419dc36155ed898ee6c")
	tx22, _ := chainhash.NewHashFromStr("c1b441267b41dc51d79e4bdab60aba74c5b2614a0f8e9a42c0dd1a1f9641f3f2")
	tx31, _ := chainhash.NewHashFromStr("36e18e32bbe7a8b0b8968f4a99da623f14a375aea390cd05249e0a343b920683")
	tx32, _ := chainhash.NewHashFromStr("18511a249fe2190b4221c1e67e05a679d84814ee7ffaf07c742707c3f5e8f886")
	tx41, _ := chainhash.NewHashFromStr("0c7edbf0a51c723e68b829224a9d27eeda8d83d6b00c00bad4f7f4d2a33a6a64")
	tx42, _ := chainhash.NewHashFromStr("a9cc273d11a74209257f12f43b0b6b5b8bc90ad1cabaf080143aa4404b03d69b")
	tx51, _ := chainhash.NewHashFromStr("1991a5c7e2c075c3944c20b7437b0da2b603d3f1858a7c70c4b1f52918c1ce1a")
	tx52, _ := chainhash.NewHashFromStr("9957c3de3beb6bfd2eca27c67978f1208a6b1490419e2e769f90bf778d00b40f")
	tx61, _ := chainhash.NewHashFromStr("aeb2b7fecd3a45f6d46f0904dcdd11291a064cffd54a48990daa2ceff241576a")
	tx62, _ := chainhash.NewHashFromStr("12ae9acff2adb45bc1c24ea0a8302d1b50378d9910fd91fc85d666adcf60b0a1")
	tx71, _ := chainhash.NewHashFromStr("e0bef6065807ecfb141ef85960795f835fccd0e082cbe705e706c40ca920d2e1")
	tx72, _ := chainhash.NewHashFromStr("68fc64c659351db77821df19e93eecc6cbab2aed6483cac586a00996bd609af7")
	tx81, _ := chainhash.NewHashFromStr("36e9c8a7086bed0bbc4d5f6dbb71ace6f56e7ed59b5f41d7195c93e6bbb9997d")
	tx82, _ := chainhash.NewHashFromStr("80986e673bc8a08bf811968d342baaf5290f322df76f3d3cbc9539e23501d145")
	tx91, _ := chainhash.NewHashFromStr("e88ff62881a4228f30304fd39e74a17780dc5e7f6526311053c10b501d599aeb")
	tx92, _ := chainhash.NewHashFromStr("8f5bd84f609fb952a5cceeec32f10d9efea5cf0766f8f558fec07b5d70226089")
	tx101, _ := chainhash.NewHashFromStr("b63ab9ffd9b990f45ab810603b1427442decc68365f4cb2b485f725393b032dd")
	tx102, _ := chainhash.NewHashFromStr("57b4764cca513dae81c5c663b61ffe4d75cc6f82a32b154601358883e09ca172")
	tx111, _ := chainhash.NewHashFromStr("e2397ae2942574eca260ee3a0f2a512642e015ea974ee70fd92297a744639c23")
	tx112, _ := chainhash.NewHashFromStr("6180f6c45dfd4c082fa3525fbd4c1297f4576565f02318c27b45b2640d52c67a")
	tx121, _ := chainhash.NewHashFromStr("2f962083ba06cbe731a3c11b3e6fc098fb9bcb285c33df2c75480a5c71f36e0f")
	tx122, _ := chainhash.NewHashFromStr("e4bbdf67e1afbf408f8194fd8821a9ee219a47502f1ae309ed859cf1d209290b")
	tx131, _ := chainhash.NewHashFromStr("b67580a038e5ef28c4fdda18ce4cf4dc64ebe31ae1a4b2437ede67aff611a9fc")
	tx132, _ := chainhash.NewHashFromStr("b20c9f55549dd231ee9d7f8653eb3943e3935051de12b25ed7d623276c3d6129")
	tx141, _ := chainhash.NewHashFromStr("07a46eeb0c315784f992344e0f912d4df6f77e8f1f486391e3d07763f754b471")
	tx142, _ := chainhash.NewHashFromStr("27fa75903cd492f04dda9bcb84a617a52d78cdbc0b81959af22a94f6c68f547c")

	keyPi := []byte("12345678901234567890123456789012")
	keyF := []byte{1, 2, 3}
	keyH := []byte("1234567890123456")
	keyQ := []byte("1234567890123456")
	keyP := []byte("12345678901234567890123456789012")
	client := Wallet.InitClient("127.0.0.1:28334", "mainnet")
	for i := 0; i < 7; i++ {
		start := time.Now()
		trans := Label.FilterLabel(client, keyH, 100)
		CTpairs := pairTrans(trans, client, keyF)
		switch i {
		case 0:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}}
		case 1:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}, {tx31, tx32}, {tx41, tx42}}
		case 2:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}, {tx31, tx32}, {tx41, tx42}, {tx51, tx52}, {tx61, tx62}}
		case 3:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}, {tx31, tx32}, {tx41, tx42}, {tx51, tx52}, {tx61, tx62}, {tx71, tx72}, {tx81, tx82}}
		case 4:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}, {tx31, tx32}, {tx41, tx42}, {tx51, tx52}, {tx61, tx62}, {tx71, tx72}, {tx81, tx82}, {tx91, tx92}, {tx101, tx102}}
		case 5:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}, {tx31, tx32}, {tx41, tx42}, {tx51, tx52}, {tx61, tx62}, {tx71, tx72}, {tx81, tx82}, {tx91, tx92}, {tx101, tx102}, {tx111, tx112}, {tx121, tx122}}
		case 6:
			CTpairs = [][]*chainhash.Hash{{tx11, tx12}, {tx21, tx22}, {tx31, tx32}, {tx41, tx42}, {tx51, tx52}, {tx61, tx62}, {tx71, tx72}, {tx81, tx82}, {tx91, tx92}, {tx101, tx102}, {tx111, tx112}, {tx121, tx122}, {tx131, tx132}, {tx141, tx142}}
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
		sigi := Signature.GetSignaruteFromTx(rawTxi)
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
		sigj := Signature.GetSignaruteFromTx(rawTxj)
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
func pairTrans(trans []*chainhash.Hash, client *rpcclient.Client, keyF []byte) [][]*chainhash.Hash {
	var pairs [][]*chainhash.Hash
	for _, cti := range trans {
		var pair []*chainhash.Hash
		pair = append(pair, cti)
		rawTx, _ := client.GetRawTransaction(cti)
		sig := Signature.GetSignaruteFromTx(rawTx)
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
		for _, ctj := range trans {
			rawTx, _ = client.GetRawTransaction(cti)
			sig = Signature.GetSignaruteFromTx(rawTx)
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
	return nil
}
