package utils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
)

func GenRsaSign(data []byte, privatePath string) (string, error) {
	sk, err := LoadPrivateKey(privatePath) //密钥签名
	if err != nil {
		return "", err
	}
	sign, err := Sha256Sign(data, sk)
	if err != nil {
		return "", err
	}
	return sign, nil
}
func Sha256Sign(origin []byte, privateKey *rsa.PrivateKey) (string, error) {
	digest := sha256.Sum256(origin)
	signed, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signed), nil
}

func AuthorizateRsa(data []byte, sign string, pubPath string) error {
	pk, err := LoadPKIXPublicKey(pubPath) //公钥验签
	if err != nil {
		return err
	}
	err = VerifySh256Sign(data, sign, pk)
	if err != nil {
		return errors.New("签名不匹配")
	}
	return nil
}
func GenRsaKeyPair(bits int) (privateKeyStr, publicKeyStr string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	privateKeyStr = string(pem.EncodeToMemory(priBlock))

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	pubBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	publicKeyStr = string(pem.EncodeToMemory(pubBlock))
	return
}

func LoadPKIXPublicKey(filePath string) (*rsa.PublicKey, error) {
	pemBlock, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBlock)
	if block == nil {
		return nil, err
	}

	v, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return v.(*rsa.PublicKey), nil
}

func ParsePublicKey(input string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(input))
	if block == nil {
		return nil, errors.New("pem decode result nil")
	}

	v, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return v.(*rsa.PublicKey), nil
}

func LoadPKCS8PrivateKey(filePath string) (*rsa.PrivateKey, error) {
	pemBlock, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBlock)
	if block == nil {
		return nil, err
	}

	v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return v.(*rsa.PrivateKey), nil
}

func LoadPublicKey(pemPath string) (*rsa.PublicKey, error) {
	pemBlock, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}

	derBlock, _ := pem.Decode(pemBlock)
	if derBlock == nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(derBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return x509Cert.PublicKey.(*rsa.PublicKey), nil
}

func LoadPrivateKey(pemPath string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	privateBlock, _ := pem.Decode(pemBytes)

	var key interface{}
	if privateBlock.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	} else if privateBlock.Type == "PRIVATE KEY" {
		key, err = x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	} else {
		err = errors.New("invaild block type")
	}
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}

func RsaPublicEncrypt(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	n := publicKey.N.BitLen()/8 - 11
	chunks := splitBuf(data, n)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, chunk)
		if err != nil {
			return encrypted, err
		}
		buffer.Write(encrypted)
	}

	return buffer.Bytes(), nil
}

func RsaPrivateDecrypt(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	n := privateKey.PublicKey.N.BitLen() / 8
	chunks := splitBuf(data, n)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, chunk)
		if err != nil {
			return decrypted, err
		}
		buffer.Write(decrypted)
	}

	return buffer.Bytes(), nil
}

func splitBuf(data []byte, n int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(data)/n+1)
	for len(data) >= n {
		chunk, data = data[:n], data[n:]
		chunks = append(chunks, chunk)
	}
	if len(data) > 0 {
		chunks = append(chunks, data[:])
	}
	return chunks
}

func SignSha1(p []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	h := sha1.New()
	h.Write(p)
	digest := h.Sum(nil)
	return privateKey.Sign(rand.Reader, digest, crypto.SHA1)
}

func SignSha2(p []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	h := sha256.New()
	h.Write(p)
	digest := h.Sum(nil)
	return privateKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func VerifySignSha1(p, signData []byte, publicKey *rsa.PublicKey) error {
	h := sha1.New()
	h.Write(p)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest, signData)
}

func VerifySignSha2(p, signData []byte, publicKey *rsa.PublicKey) error {
	h := sha256.New()
	h.Write(p)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signData)
}

func Sha1Sign(p []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	digest := sha1.Sum(p)
	return privateKey.Sign(rand.Reader, digest[:], crypto.SHA1)
}

func VerifySh1Sign(p, signData []byte, publicKey *rsa.PublicKey) error {
	digest := sha1.Sum(p)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest[:], signData)
}

func VerifySh256Sign(origin []byte, sign string, publicKey *rsa.PublicKey) error {
	decoded, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(origin)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], decoded)
}

// copy from crypt/rsa/pkcs1v5.go
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// copy from crypt/rsa/pkcs1v5.go
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// copy from crypt/rsa/pkcs1v5.go
func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}

// copy from crypt/rsa/pkcs1v5.go
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
func unLeftPad(input []byte) (out []byte) {
	n := len(input)
	t := 2
	for i := 2; i < n; i++ {
		if input[i] == 0xff {
			t = t + 1
		} else {
			if input[i] == input[0] {
				t = t + int(input[1])
			}
			break
		}
	}
	out = make([]byte, n-t)
	copy(out, input[t:])
	return
}

// copy&modified from crypt/rsa/pkcs1v5.go
func publicDecrypt(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) (out []byte, err error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := (pub.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, fmt.Errorf("length illegal")
	}

	c := new(big.Int).SetBytes(sig)
	m := encrypt(new(big.Int), pub, c)
	em := leftPad(m.Bytes(), k)
	out = unLeftPad(em)

	err = nil
	return
}

func PrivateEncrypt(privt *rsa.PrivateKey, data []byte) ([]byte, error) {
	signData, err := rsa.SignPKCS1v15(nil, privt, crypto.Hash(0), data)
	if err != nil {
		return nil, err
	}
	return signData, nil
}
func PublicDecrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	decData, err := publicDecrypt(pub, crypto.Hash(0), nil, data)
	if err != nil {
		return nil, err
	}
	return decData, nil
}

func ParseCert(input string) (*x509.CertPool, error) {
	cert := x509.NewCertPool()
	ok := cert.AppendCertsFromPEM([]byte(input))
	if !ok {
		err := fmt.Errorf("证书无效")
		return nil, err
	}
	return cert, nil
}
