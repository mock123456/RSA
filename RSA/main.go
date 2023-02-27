package main

import (
	"RSA/test"
	"fmt"
)

func main() {
	RsaTest()
}

func RsaTest() {
	err := test.RsaGenKey(2048)
	if err != nil {
		fmt.Println("错误信息", err)
	}
	//加密
	src := []byte("早日实现榴莲自由")
	data, err := test.RsaPublicEncrypt(src, []byte("public.pem"))
	if err == nil {
		fmt.Println("错误信息", err)
	}
	//解密
	data, err = test.RsaPrivateDecrypt(data, "private.pem")
	if err != nil {
		fmt.Println("错误信息", err)
	}
	fmt.Println("非对称加密结果:" + string(data))

}
