package main

import (
	"DDSAC/Signature"
	"DDSAC/Wallet"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

func main() {
	client := Wallet.InitClient("127.0.0.1:28334", "mainnet")
	txs := GetTransFromBlock(client, 867400, 867423)
	cnt := 0
	for _, txid := range txs {
		rawTx, _ := client.GetRawTransaction(txid)
		tx, _ := client.GetRawTransactionVerbose(txid)
		if tx.Vin[0].ScriptSig == nil {
			continue
		}
		sig := Signature.GetSignaruteFromTx(rawTx)
		// 不讨论隔离见证
		if sig != nil {
			fmt.Println(txid)
			cnt++
			if cnt == 30 {
				break
			}
		}
	}
}
func GetTransFromBlock(client *rpcclient.Client, hb, he int64) []*chainhash.Hash {
	var txids []*chainhash.Hash
	//t, _ := client.GetBlockCount()
	// 获取指定高度的区块哈希
	for height := hb; height <= he; height++ {
		blockHash, err := client.GetBlockHash(height)
		if err != nil {
			fmt.Printf("获取区块哈希失败 (高度: %d): %v\n", height, err)
		}
		block, err := client.GetBlockVerbose(blockHash)
		if err != nil {
			fmt.Printf("获取区块详情失败 (哈希: %s): %v\n", blockHash, err)
		}
		// 遍历区块中的每个交易
		for _, txID := range block.Tx {
			txid, _ := chainhash.NewHashFromStr(txID)
			txids = append(txids, txid)
		}
	}
	return txids
}
