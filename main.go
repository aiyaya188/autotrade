package main

import (
	"autotrade/utils"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
func main() {
	FutrueOrder()
	//fundAssets()
	return
	utils.InitHttpClient()
	head := make(map[string]string)
	head["X-MBX-APIKEY"] = "xWu5ieyfz8HwH79LLi19xIweXUMnIl4UxLmT5YrNvlAUSrnMPkDSbcD1jskRTGS1"
	st := "https://api1.binance.com/api/v3/time"
	res1, err1 := utils.DoGet(st, head)
	if err1 != nil {
		fmt.Println("err1:", err1)
		return
	}

	fmt.Println("res1:", res1)
	return
	cur := time.Now().UnixMilli()
	data := fmt.Sprintf("recvWindow=%v&timestamp=%v", 60000, cur)
	secret := "TrGywsUqwIseZhzELY8SEX8QmIemyPsIlzgHsH2bUi2j14WrDr9nftJjLdet0cRc"
	sig := hmacSha256(data, secret)
	fmt.Println("tt:", data)
	fmt.Println("sig:", sig)
	addr := fmt.Sprintf("https://api1.binance.com/sapi/v1/capital/config/getall?recvWindow=%v&timestamp=%v&signature=%v", 60000, cur, sig)
	res, err := utils.DoGet(addr, head)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println("res:", res)

}
