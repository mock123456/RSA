package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// 生成公钥和私钥的函数
func RsaGenKey(bits int) error {

	//私钥生成

	//1.使用rsa.GenerateKey()函数生成私钥
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//2.通过x.509标准将得到的RSA私钥序列化为ASN.1的 DER 编码字符串
	privStream := x509.MarshalPKCS1PrivateKey(privKey)
	//3.将私钥字符串设置到pem格式串中
	block := pem.Block{
		Type:    "RSA Private Ket ",
		Headers: nil,
		Bytes:   privStream,
	}
	//4.通过pem将设置好的数据进行编码，并写入磁盘文件中
	privFile, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(privFile, &block)
	if err != nil {
		return err
	}
	privFile.Close()

	//公钥生成

	//step1:从得到的私钥对象从公钥信息中取来
	pubKey := privKey.PublicKey

	//step2:通过x.509标准将得到的rsa公钥序列化为字符串 write private.pem`: Access is denied.
	pubStream, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return err
	}
	//step3:将公钥字符串设置到pem格式串中
	block = pem.Block{
		Type:    "RSA Public Key",
		Headers: nil,
		Bytes:   pubStream,
	}
	//step4:通过pem将设置好的数据进行编码，并写入到磁盘文件中
	pubFile, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer pubFile.Close()
	err = pem.Encode(pubFile, &block)
	if err != nil {
		return err
	}
	return nil

}
