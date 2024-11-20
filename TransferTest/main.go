// 向指定地址转入UTXO以便于地址后续的转账操作
package main

import (
	"DDSAC/Crypto"
	"DDSAC/Key"
	"DDSAC/Transaction"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
	"strconv"
)

func main() {

}
func generateSourceAddrPair(num int) [][]string {
	var sourceAddrPair [][]string
	for i := 0; i < num; i++ {
		addresses := generatePrikPair([]byte(strconv.Itoa(i)), keyQ, client)
		// 从挖矿地址向源地址转入1笔utxo以便源地址发送交易
		_, err := Transaction.EntireSendTrans(miningAddr, addresses[0], 40*1e8, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		_, err = Transaction.EntireSendTrans(miningAddr, addresses[1], 40*1e8, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		sourceAddrPair = append(sourceAddrPair, addresses)
	}
	return sourceAddrPair
}
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
