package bian

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	HttpClient *http.Client
	ApiKey     string
	SecretKey  string
	Url        string
}

/*
		proxy_raw := "i536.kdltps.com:15818"
		proxy_str := fmt.Sprintf("http://%s:%s@%s", username, password, proxy_raw)
		proxy, err := url.Parse(proxy_str)
		if err != nil {
			return nil, err
		}
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}

*/
func NewClient(Url, ApiKey, secret string) (*Client, error) {
	client := new(Client)
	client.HttpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:     true,
			MaxIdleConnsPerHost:   -1,
			ResponseHeaderTimeout: 10 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}
	client.SecretKey = secret
	client.Url = Url
	client.ApiKey = ApiKey
	return client, nil
}
func (c *Client) DoPost(addr string, Header map[string]string, body string, jsonFormat bool) (string, error) {
	req, err := http.NewRequest("POST", addr, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	if Header != nil {
		for k, v := range Header {
			req.Header.Set(k, v)
		}
	}
	if jsonFormat {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.Body != nil {
		respon, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		return string(respon), nil
	}
	return "", nil
}

//DoGet
func (c *Client) DoGet(addr string, Header map[string]string) (string, error) {
	//var err error
	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		return "", err
	}

	if Header != nil {
		for k, v := range Header {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "", err
	}

	respon, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return "", err
	}
	resp.Body.Close()
	return string(respon), nil
}
func (c *Client) Sign(data string) string {
	sig := hmacSha256(data, c.SecretKey)
	return sig
}
func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
