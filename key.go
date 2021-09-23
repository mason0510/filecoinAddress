package main

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/filecoin-project/go-address"
	goCrypto "github.com/filecoin-project/go-crypto"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/minio/blake2b-simd"
)

const encodeStd = "abcdefghijklmnopqrstuvwxyz234567"

var AddressEncoding = base32.NewEncoding(encodeStd)
var checksumHashConfig = &blake2b.Config{Size: 4}

func main() {
	//k, err := GenPrivate()
	var err error
	//测试代码
	k := []byte{126, 25, 208, 242, 124, 230, 119, 157, 89, 166, 200, 224, 212, 218, 245, 211, 223, 67, 202, 62, 5, 222, 129, 216, 251, 87, 113, 250, 62, 248, 118, 12}
	fmt.Println("私钥数组：", k, ",长度：", len(k), err)
	p, err := ToPublic(k)
	fmt.Println("公钥数组：", p, ",长度：", len(p), err)

	var payloadHashConfig = &blake2b.Config{Size: 20}
	b20 := hash(p, payloadHashConfig)
	fmt.Println("通过公钥blake2b/20 得到数组 ", b20)
	explen := 1 + len(b20)
	buf := make([]byte, explen)
	buf[0] = address.SECP256K1
	copy(buf[1:], b20)
	fmt.Println("得到21数组 ", buf)
	cksm := Checksum(buf)
	fmt.Println("通过21数组 blake2b/4，得到数组 ", cksm)

	codeBuf := make([]byte, 0)
	codeBuf = append(codeBuf, b20[:]...)
	codeBuf = append(codeBuf, cksm[:]...)
	fmt.Println("20和4的数组组合 ", codeBuf)
	str := AddressEncoding.WithPadding(-1).EncodeToString(codeBuf)
	fmt.Println("通过base 32 padding -1 encode 得来字符串 ", str)
	re := "t1" + str
	fmt.Println("加上前缀得最终结果 ", re)

	prikeyBase64Str := base64.StdEncoding.EncodeToString(k)
	pubkeyBase64Str := base64.StdEncoding.EncodeToString(p)
	fmt.Println("公私钥base64 私钥：", prikeyBase64Str, "，公钥：", pubkeyBase64Str)
	priHex := hex.EncodeToString(k)
	pubHex := hex.EncodeToString(p)
	fmt.Println("公私钥hex 私钥len:", len(priHex)/2, "：", priHex, "，公钥len:", len(pubHex)/2, "：", pubHex)

	//keystore文件
	kStr := "wallet-" + re
	//kStr = "default" // 设置节点默认账号,结果是MRSWMYLVNR2A
	encName := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(kStr))
	fmt.Println("keystore文件名： " + encName)
	kinfo := &types.KeyInfo{
		Type:       types.KTSecp256k1,
		PrivateKey: k,
	}

	kb, _ := json.Marshal(kinfo)
	fmt.Println(string(kb))
	fmt.Println(hex.EncodeToString(kb))

	ssss := "{\"Type\":\"secp256k1\",\"PrivateKey\":\"fhnQ8nzmd51Zpsjg1Nr1099Dyj4F3oHY+1dx+j74dgw=\"}"
	fmt.Println(hex.EncodeToString([]byte(ssss)))
}

func GenPrivate() ([]byte, error) {
	priv, err := goCrypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return priv, nil
}
func ToPublic(pk []byte) ([]byte, error) {
	return goCrypto.PublicKey(pk), nil
}

func hash(ingest []byte, cfg *blake2b.Config) []byte {
	hasher, err := blake2b.New(cfg)
	if err != nil {
		// If this happens sth is very wrong.
		panic(fmt.Sprintf("invalid address hash configuration: %v", err)) // ok
	}
	if _, err := hasher.Write(ingest); err != nil {
		// blake2bs Write implementation never returns an error in its current
		// setup. So if this happens sth went very wrong.
		panic(fmt.Sprintf("blake2b is unable to process hashes: %v", err)) // ok
	}
	return hasher.Sum(nil)
}

// ValidateChecksum returns true if the checksum of `ingest` is equal to `expected`>
func ValidateChecksum(ingest, expect []byte) bool {
	digest := Checksum(ingest)
	return bytes.Equal(digest, expect)
}

// Checksum returns the checksum of `ingest`.
func Checksum(ingest []byte) []byte {
	return hash(ingest, checksumHashConfig)
}
