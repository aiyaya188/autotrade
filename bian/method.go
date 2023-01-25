package bian

import (
	"encoding/json"
	"fmt"
)

//获取系统时间
//	{"serverTime":1671271784593}
type SysTime struct {
	ServerTime int64 `json:"serverTime"`
}

func (c *Client) SysTime() (int64, error) {
	head := make(map[string]string)
	head["X-MBX-APIKEY"] = c.ApiKey
	addr := c.Url + "api/v3/time"
	res, err := c.DoGet(addr, head)
	if err != nil {
		return 0, err
	}
	var st SysTime
	json.Unmarshal([]byte(res), &st)
	return st.ServerTime, nil
}

//获取资金账户
func (c *Client) FoundAssets() error {
	head := make(map[string]string)
	head["X-MBX-APIKEY"] = c.ApiKey
	addr := c.Url + "sapi/v1/asset/get-funding-asset"
	st, err := c.SysTime()
	if err != nil {
		return err
	}
	dataSig := fmt.Sprintf("recvWindow=%v&timestamp=%v", 60000, st)
	sig := c.Sign(dataSig)
	body := dataSig + "&signature=" + sig
	res, err := c.DoPost(addr, head, body, false)
	if err != nil {
		return err
	}
	fmt.Println("res:", res)
	return nil
}

//获取资金账户
func (c *Client) AccountSnapshot(accountType string) error {
	head := make(map[string]string)
	head["X-MBX-APIKEY"] = c.ApiKey
	addr := c.Url + "sapi/v1/accountSnapshot"
	st, err := c.SysTime()
	if err != nil {
		return err
	}
	dataSig := fmt.Sprintf("type=%v&recvWindow=%v&timestamp=%v", accountType, 60000, st)
	//addr := fmt.Sprintf("https://api1.binance.com/sapi/v1/capital/config/getall?recvWindow=%v&timestamp=%v&signature=%v", 60000, cur, sig)
	sig := c.Sign(dataSig)
	body := dataSig + "&signature=" + sig
	addr = addr + "?" + body
	//res, err := c.DoPost(addr, head, body, false)
	res, err := c.DoGet(addr, head)
	if err != nil {
		return err
	}
	fmt.Println("res:", res)
	return nil
}

//账户余额,合约
func (c *Client) AccountBalanceFutrue() error {
	head := make(map[string]string)
	head["X-MBX-APIKEY"] = c.ApiKey
	addr := c.Url + "/fapi/v2/account"
	st, err := c.SysTime()
	if err != nil {
		return err
	}
	dataSig := fmt.Sprintf("recvWindow=%v&timestamp=%v", 60000, st)
	sig := c.Sign(dataSig)
	body := dataSig + "&signature=" + sig
	addr = addr + "?" + body
	//res, err := c.DoPost(addr, head, body, false)
	res, err := c.DoGet(addr, head)
	if err != nil {
		return err
	}
	fmt.Println("res:", res)
	return nil
}

func (c *Client) OrderInfo() error {
	head := make(map[string]string)
	head["X-MBX-APIKEY"] = c.ApiKey
	addr := c.Url + "/fapi/v1/allOrders"
	st, err := c.SysTime()
	if err != nil {
		return err
	}
	dataSig := fmt.Sprintf("symbol=%v&recvWindow=%v&timestamp=%v", "ETHUSDT", 60000, st)
	sig := c.Sign(dataSig)
	body := dataSig + "&signature=" + sig
	addr = addr + "?" + body
	//res, err := c.DoPost(addr, head, body, false)
	res, err := c.DoGet(addr, head)
	if err != nil {
		return err
	}
	fmt.Println("res:", res)
	return nil
}
