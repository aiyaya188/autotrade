package main

import (
	"autotrade/bian"
	"fmt"
)

func fundAssets() {
	url := "https://api1.binance.com/"
	apiKey := "1zEyasZYUfZHzZEmd2xvR3ZUL1zcxMypStf0wdKbZCA663bNtIuqDrvG9GzmMUw9"
	secret := "4VfsSUc8bk9rt80slhqrqGmhgXZ1qu1hsFSAvIpobtnwcgThLXo1LVjk2LD7TCDn"
	client, err := bian.NewClient(url, apiKey, secret)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	if err := client.FoundAssets(); err != nil {
		fmt.Println("err:", err)
		return
	}

	if err := client.AccountSnapshot("SPOT"); err != nil {
		fmt.Println("err:", err)
		return

	}
}
func FutrueBalance() {
	url := "https://fapi.binance.com/"
	apiKey := "1zEyasZYUfZHzZEmd2xvR3ZUL1zcxMypStf0wdKbZCA663bNtIuqDrvG9GzmMUw9"
	secret := "4VfsSUc8bk9rt80slhqrqGmhgXZ1qu1hsFSAvIpobtnwcgThLXo1LVjk2LD7TCDn"
	client, err := bian.NewClient(url, apiKey, secret)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	if err := client.AccountBalanceFutrue(); err != nil {
		fmt.Println("err:", err)
		return
	}

}

func FutrueOrder() {
	url := "https://fapi.binance.com/"
	apiKey := "1zEyasZYUfZHzZEmd2xvR3ZUL1zcxMypStf0wdKbZCA663bNtIuqDrvG9GzmMUw9"
	secret := "4VfsSUc8bk9rt80slhqrqGmhgXZ1qu1hsFSAvIpobtnwcgThLXo1LVjk2LD7TCDn"
	client, err := bian.NewClient(url, apiKey, secret)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	if err := client.OrderInfo(); err != nil {
		fmt.Println("err:", err)
		return
	}

}
