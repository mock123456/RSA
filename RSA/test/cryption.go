package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// 公钥加密函数,src待加密的数据，pathName公钥文件的路径
func RsaPublicEncrypt(src []byte, pathName []byte) ([]byte, error) {
	msg := []byte(" ")
	//1.将公钥从文件中读出来，得到使用pem编码的字符串
	file, err := os.Open(string(pathName))
	if err != nil {
		return msg, err
	}
	//1.1先得到文件属性信息，再通过文件属性信息得到文件大小
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	recevBuf := make([]byte, info.Size())
	_, err = file.Read(recevBuf)
	if err != nil {
		return msg, err
	}
	//2.将得到的字符串解码
	block, _ := pem.Decode(recevBuf)
	//3.使用X509将编码之后的公钥解析出来
	pubInter, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return msg, err
	}
	pubKey := pubInter.(*rsa.PublicKey)
	//4.使用得到的公钥对信息进行RSA加密
	msg, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
	if err != nil {
		return msg, err
	}
	return msg, nil

}

//私钥解密函数

func RsaPrivateDecrypt(src []byte, pathName string) ([]byte, error) {
	msg := []byte(" ")
	//1.打开私钥文件
	file, err := os.Open(pathName)
	if err != nil {
		return msg, err
	}
	//2.读文件
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	recvBUF := make([]byte, info.Size())
	_, err = file.Read(recvBUF)
	if err != nil {
		return msg, err
	}
	//3.将得到的字符串解码
	block, _ := pem.Decode(recvBUF)
	//4.通过X509还原私钥数据
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return msg, err
	}
	msg, err = rsa.DecryptPKCS1v15(rand.Reader, privKey, src)
	if err != nil {
		return msg, nil
	}
	return msg, nil
}
