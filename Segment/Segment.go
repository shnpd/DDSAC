package Segment

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// Segment 将密文分组，每组256比特用字符串表示，返回字符串数组
func Segment(cipher []byte) []string {
	binaryCipher := ConvertToBinary(cipher)
	//endFlag := getEndFlag()
	endFlag := ConvertToBinary([]byte{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04})
	U := 256
	// 片段总数，除法向上取整
	TF := fmt.Sprintf("%08b", uint8((len(binaryCipher)+(U-15))/(U-16)))
	var b []string
	var payload string
	IF := -1
	for i := 0; i < len(binaryCipher); i += 240 {
		IF++
		if i+240 > len(binaryCipher) {
			payload = binaryCipher[i:]
		} else {
			payload = binaryCipher[i : i+240]
		}
		bi := TF + fmt.Sprintf("%08b", IF) + payload
		b = append(b, bi)
	}
	// 添加256比特的endflag首先补齐最后一个payload，剩下的再添加一个分组
	minus := U - len(b[len(b)-1])
	b[len(b)-1] += endFlag[:minus]
	b = append(b, endFlag[minus:])
	// 补齐最后一个分组为U比特
	b[len(b)-1] = pad(b[len(b)-1], U)
	return b
}

// pad 使用1填充字符串为指定大小
func pad(b string, size int) string {
	padding := size - len(b)%size
	return b + strings.Repeat("1", padding)
}

// getEndFlag 随机生成结束标志
func getEndFlag() string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
		return ""
	}
	endFlag := ConvertToBinary(randomBytes)
	return endFlag
}

// ConvertToBinary 将字节数组转为字符串，每个字节转为8比特二进制字符串
func ConvertToBinary(data []byte) string {
	var binaryStr string
	for _, b := range data {
		binaryStr += fmt.Sprintf("%08b", b)
	}
	return binaryStr
}
