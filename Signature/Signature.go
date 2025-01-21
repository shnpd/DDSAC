package Signature

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"log"
	"strconv"
)

// GetSigFromTx 从交易id查询交易签名
func GetSigFromTx(client *rpcclient.Client, txid *chainhash.Hash) string {
	rawtx, err := client.GetRawTransaction(txid)
	if err != nil {
		log.Fatal(err)
	}
	sigScript := hex.EncodeToString(rawtx.MsgTx().TxIn[0].SignatureScript)
	sigScript = sigScript[2:]
	length := sigScript[2:4]
	lenSig, _ := strconv.ParseInt(length, 16, 10)
	sigScript = sigScript[0 : 4+lenSig*2]
	return sigScript
}

// getsigFromHex 从Hex字段提取签名
func getsigFromHex(HexSig string) (*ecdsa.Signature, error) {
	lenSigByte := HexSig[4:6]
	t, err := strconv.ParseInt(lenSigByte, 16, 0)
	if err != nil {
		return nil, err
	}
	sigStr := HexSig[2 : 6+2*t]
	//解码
	asmByte, err := hex.DecodeString(sigStr)
	if err != nil {
		return nil, err
	}
	sig, err := ecdsa.ParseDERSignature(asmByte)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// getSignaruteFromTx 提取交易签名
func GetSignaruteFromTx(signatureScript string) *ecdsa.Signature {
	//signatureScript := hex.EncodeToString(rawTx.MsgTx().TxIn[0].SignatureScript)
	// 不讨论隔离见证的情况
	if signatureScript == "" {
		return nil
	}
	sig, err := getsigFromHex(signatureScript)
	if err != nil {
		return nil
	}
	r := sig.R()
	s := sig.S()
	//if Share.IsTxSignOver[*rawTx.Hash()] {
	//	s.Negate()
	//}
	sigOrigin := ecdsa.NewSignature(&r, &s)
	return sigOrigin
}

// GetHashFromTx 提取交易签名数据
func GetHashFromTx(rawTx *btcutil.Tx, client *rpcclient.Client) ([]byte, error) {
	var script []byte
	var hashType txscript.SigHashType
	tx := new(wire.MsgTx)
	var idx int
	idx = 0
	tx = rawTx.MsgTx()
	hashType = 1
	script = getScript(rawTx.MsgTx(), client)
	hash, err := txscript.CalcSignatureHash(script, hashType, tx, idx)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// getScript 获取生成utxo的交易的输出脚本
func getScript(tx *wire.MsgTx, client *rpcclient.Client) []byte {
	txhash := tx.TxIn[0].PreviousOutPoint.Hash
	txraw, _ := client.GetRawTransaction(&txhash)
	script := txraw.MsgTx().TxOut[0].PkScript
	return script
}
