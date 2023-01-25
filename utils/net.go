package utils

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var HttpClient *http.Client

func InitHttpClient() {
	HttpClient = &http.Client{
		//Timeout: 500 * time.Millisecond,
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			//AllowHTTP: true,
			//Dial:                  dialer.Dial,
			DisableKeepAlives:     true,
			MaxIdleConnsPerHost:   -1,
			ResponseHeaderTimeout: 10 * time.Second,
			//TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func DoPost(addr string, Header map[string]string, body string, jsonFormat bool) (string, error) {
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
	resp, err := HttpClient.Do(req)
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
func DoGet(addr string, Header map[string]string) (string, error) {
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

	resp, err := HttpClient.Do(req)
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
