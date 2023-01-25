package utils

import (
	"bytes"
	"encoding/base64"
	"github.com/pquerna/otp/totp"
	"image/png"
)

func Create2FAQRByName(account string, name string) (string, string, error) {
	issuer := name
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", err
	}
	err = png.Encode(&buf, img)
	if err != nil {
		return "", "", err
	}
	pngbase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return key.Secret(), pngbase64, nil
}

//ValidTotp 校验totp验证码
func ValidTotp(passcord, secret string) bool {
	return totp.Validate(passcord, secret)
}

func GetTotp(userName string, name string) (map[string]string, error) {
	//新增totp secret code
	secret, png, err := Create2FAQRByName(userName, name)
	if err != nil {
		return nil, err
	}
	//创建totp二维码
	totp := make(map[string]string)
	totp["qrcode"] = "data:image/png;base64," + png
	totp["secret"] = secret
	return totp, nil
}
