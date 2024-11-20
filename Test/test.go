package main

import (
	"fmt"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
	"strconv"
)

func main() {
	connCfg := &rpcclient.ConnConfig{
		Host:         "127.0.0.1:28334",
		User:         "mainnet",
		Pass:         "mainnet",
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	num, _ := client.GetBlockCount()
	fmt.Println(num)
	//	keyH := []byte("1234567890123456")
	//	txs := Label.FilterLabel(client, keyH, 10)
	//	pair := pairTrans(txs)
	//	fmt.Println(pair)
	//for i := 0; i < 30; i++ {
	//	address, err := client.GetNewAddress("default")
	//	if err != nil {
	//		fmt.Println(err)
	//	}
	//	fmt.Println(address)
	//}
	//generate, err := client.Generate(299)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(generate)
}
func covertStr2Byte(bitstr string) []byte {
	var bytes []byte
	//	将256比特的二进制字符串转为字节数组再计算加密
	// 每 8 位解析为一个字节
	for i := 0; i < len(bitstr); i += 8 {
		byteStr := bitstr[i : i+8]
		// 将二进制字符串解析为整数
		parsedByte, _ := strconv.ParseUint(byteStr, 2, 8)
		bytes = append(bytes, byte(parsedByte))
	}
	return bytes
}
