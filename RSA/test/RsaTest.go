package test

import "fmt"

func RsaTest() {
	err := RsaGenKey(2048)

	fmt.Println("错误信息", err)
	//data, err := RsaPublicEncrypt(src, "../RSA/public.pem")

}
