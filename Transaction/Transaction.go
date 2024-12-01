// Package Transaction 交易相关的方法，包括创建交易，签名交易，广播交易
package Transaction

import (
	"DDSAC/Wallet"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

var client = Wallet.InitClient("127.0.0.1:28335", "simnet")

// EntireSendTrans 完整交易发送，包括交易生成、交易签名、交易广播，最终返回广播的交易id
func EntireSendTrans(sourceAddr, destAddr string, amount int64, embedMsg *[]byte) (string, error) {
	rawTx, err := GenerateTrans(sourceAddr, destAddr, amount)
	if err != nil {
		return "", err
	}
	signTx, err := SignTrans(rawTx, embedMsg)
	if err != nil {
		return "", err
	}
	transId, err := BroadTrans(signTx)
	if err != nil {
		return "", err
	}
	return transId, nil
}

// GenerateTrans 生成sourceAddr到destAddr的原始交易,输出金额amount单位为聪
func GenerateTrans(sourceAddr, destAddr string, amount int64) (*wire.MsgTx, error) {
	// 筛选源地址的UTXO
	utxos, _ := client.ListUnspent()
	var sourceUTXO btcjson.ListUnspentResult
	for i, utxo := range utxos {
		if utxo.Address == sourceAddr {
			sourceUTXO = utxo
			break
		}
		if i == len(utxos)-1 {
			return nil, fmt.Errorf("UTXO not found")
		}
	}
	// 构造输入
	var inputs []btcjson.TransactionInput
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: sourceUTXO.TxID,
		Vout: sourceUTXO.Vout,
	})
	//	构造输出
	outAddr, _ := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	outputs := map[btcutil.Address]btcutil.Amount{
		//outAddr: btcutil.Amount(amount),
		outAddr: btcutil.Amount((sourceUTXO.Amount - 0.1) * 1e8),
	}
	//	创建交易
	rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		fmt.Println(sourceUTXO.Amount)
		return nil, fmt.Errorf("error creating raw transaction: %v", err)
	}
	return rawTx, nil
}

// SignTrans 签名交易，输入的embedMsg为计算签名所使用的随机因子，返回签名后的交易
func SignTrans(rawTx *wire.MsgTx, embedMsg *[]byte) (*wire.MsgTx, error) {
	signedTx, complete, err, _ := client.SignRawTransaction(rawTx, embedMsg)
	if err != nil {
		return nil, fmt.Errorf("error signing transaction: %v", err)
	}
	if !complete {
		return nil, fmt.Errorf("transaction signing incomplete")
	}
	return signedTx, nil
}

// BroadTrans 广播交易
func BroadTrans(signedTx *wire.MsgTx) (string, error) {
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		return "", fmt.Errorf("SendRawTransaction error: %v", err)
	}
	return txHash.String(), nil
}
