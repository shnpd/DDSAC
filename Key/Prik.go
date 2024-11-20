// Package Key 密钥相关操作，例如：密钥导入钱包、生成地址等
package Key

import (
	"crypto/sha256"
	"errors"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	mndrixBtcutil "github.com/mndrix/btcutil" //椭圆曲线
)

var (
	//定义曲线
	curve = mndrixBtcutil.Secp256k1()
	//定义曲线参数
	curveParams = curve.Params()
	//	定义网络类型
	netType = "simnet"
)

// ToWIF 将私钥转换为 WIF 格式
func ToWIF(privateKey []byte) (string, error) {
	// 选择网络字节
	var networkByte byte
	switch netType {
	case "mainnet":
		networkByte = 0x80 // 主网
	case "testnet":
		networkByte = 0xEF // 测试网
	case "simnet":
		networkByte = 0x64 //模拟网
	default:
		return "", errors.New("netType error")
	}
	// 创建新的字节数组，长度为私钥长度 + 1 + 4（校验和）
	wif := make([]byte, 0, len(privateKey)+1+4)
	wif = append(wif, networkByte)   // 添加网络字节
	wif = append(wif, privateKey...) // 添加私钥
	// 计算校验和
	checksum := sha256.Sum256(wif)        // 第一次SHA-256
	checksum = sha256.Sum256(checksum[:]) // 第二次SHA-256
	checksum2 := checksum[:4]             // 取前4字节作为校验和
	// 将校验和添加到WIF末尾
	wif = append(wif, checksum2...)
	// 进行Base58编码
	return base58.Encode(wif), nil
}
func ImportPrivkey(key []byte, client *rpcclient.Client) error {
	prikWIF, err := ToWIF(key)
	if err != nil {
		return err
	}
	wif, _ := btcutil.DecodeWIF(prikWIF)
	err = client.ImportPrivKey(wif)
	if err != nil {
		return err
	}
	return nil
}

// GetAddressByWIF 根据wif私钥获取对应的地址
func GetAddressByWIF(wif string) (string, error) {
	var param chaincfg.Params
	switch netType {
	case "simnet":
		param = chaincfg.SimNetParams
	case "testnet":
		param = chaincfg.TestNet3Params
	case "mainnet":
		param = chaincfg.MainNetParams
	default:
		return "", errors.New("error netType")
	}
	// 解析WIF格式
	privKey, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return "", err
	}
	// 计算公钥
	pubKey := privKey.PrivKey.PubKey()
	// 生成地址
	addrPk, err := btcutil.NewAddressPubKey(pubKey.SerializeUncompressed(), &param)
	if err != nil {
		return "", err
	}
	// 输出地址
	addr := addrPk.EncodeAddress()
	return addr, nil
}

// GetAddressByPrivKey 根据PrivateKey获取对应的地址
func GetAddressByPrivKey(key []byte) (string, error) {
	prikWIF, err := ToWIF(key)
	if err != nil {
		return "", err
	}
	address, err := GetAddressByWIF(prikWIF)
	if err != nil {
		return "", err
	}
	return address, nil
}
