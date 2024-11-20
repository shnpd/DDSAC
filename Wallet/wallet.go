// Package Wallet 初始化钱包
package Wallet

import (
	"fmt"
	"github.com/btcsuite/btcd/rpcclient"
)

func InitWallet() *rpcclient.Client {
	// 设置RPC客户端连接的配置
	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:28335", // 替换为你的btcwallet的RPC地址
		User:         "simnet",          // 在btcwallet配置文件中定义的RPC用户名
		Pass:         "simnet",          // 在btcwallet配置文件中定义的RPC密码
		HTTPPostMode: true,              // 使用HTTP POST模式
		DisableTLS:   true,              // 禁用TLS
		Params:       "simnet",          // 连接到simnet网
	}

	// 创建新的RPC客户端
	client, _ := rpcclient.New(connCfg, nil)
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		fmt.Println(err)
	}
	return client
}
