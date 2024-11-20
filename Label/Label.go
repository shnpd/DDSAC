// Package Label 标签操作，生成标签
package Label

import (
	"DDSAC/Crypto"
	"DDSAC/Wallet"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"math/big"
)

func FilterLabel(client *rpcclient.Client, keyH []byte, wh int64) []*chainhash.Hash {
	var CTs []*chainhash.Hash
	// 筛选第i个窗口的交易
	i := int64(24)
	hb := (i - 1) * wh
	he := i*wh - 1

	// 第i个窗口的交易标签从它前一个窗口抽样
	lb := (i - 2) * wh
	le := (i-1)*wh - 1

	NAL := GetAmountFromBlock(lb, le)
	Txs := GetTransFromBlock(hb, he)
	for _, txid := range Txs {
		transaction, _ := client.GetTransaction(txid)
		if transaction.Details[0].Category == "immature" || transaction.Details[1].Amount == 50 {
			continue
		}
		outAddr := transaction.Details[1].Address
		amount := int64(transaction.Details[1].Amount) * 1e8
		index := Crypto.PRF([]byte(outAddr), keyH)
		bigInt := new(big.Int).SetBytes(index)
		mod := big.NewInt(int64(len(NAL)))
		reminder := new(big.Int).Mod(bigInt, mod)
		if amount == NAL[reminder.Int64()] {
			CTs = append(CTs, txid)
		}
	}
	return CTs
}

// GenerateLabel 输入输出地址集、PRF密钥、滑动区块高度大小，输出选取的金额标签
func GenerateLabel(client *rpcclient.Client, afs []string, keyH []byte, wh int64) []int64 {
	// 记录标签即输出金额，单位为聪
	var lfs []int64
	max_height, _ := client.GetBlockCount()
	windex := max_height / wh
	hb := (windex - 1) * wh
	he := windex*wh - 1
	NAL := GetAmountFromBlock(hb, he)
	for _, v := range afs {
		// 计算输出地址哈希
		index := Crypto.PRF([]byte(v), keyH)
		// 将哈希结果字节数组转为int，计算reminder
		bigInt := new(big.Int).SetBytes(index)
		mod := big.NewInt(int64(len(NAL)))
		reminder := new(big.Int).Mod(bigInt, mod)
		amount := NAL[reminder.Int64()]
		lfs = append(lfs, amount)
	}
	return lfs
}

// GetAmountFromBlock 获取区块高度从hb到he的交易的输出金额
func GetAmountFromBlock(hb, he int64) []int64 {
	var amount []int64
	client := Wallet.InitWallet()
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
			// 遍历每个交易的输出
			tx, _ := client.GetRawTransaction(txid)
			for _, out := range tx.MsgTx().TxOut {
				amount = append(amount, out.Value)
			}
		}
	}
	return amount
}

// GetTransFromBlock 获取区块高度从hb到he的所有交易
func GetTransFromBlock(hb, he int64) []*chainhash.Hash {
	var txids []*chainhash.Hash
	client := Wallet.InitWallet()
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