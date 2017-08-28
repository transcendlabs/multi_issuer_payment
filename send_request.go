package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/tendermint/go-crypto"
	"io/ioutil"
	"net/http"
	"os"
)

/*
func main() {
	issue()
	transact()

}
*/

func issue() {
	fmt.Print("Enter UserAddress: ")
	var userAddress string
	fmt.Scanln(&userAddress)

	fmt.Print("Enter numTokens: ")
	var numTokens string
	fmt.Scanln(&numTokens)

	fmt.Print("Enter sequence: ")
	var sequence string
	fmt.Scanln(&sequence)

	sign := GetSignatureIssueToken(userAddress, numTokens, sequence)

	url := "http://localhost:46657/broadcast_tx_commit?tx=\"issueTokens," +
		"" + userAddress + "," + numTokens + "," + sequence + "," + sign + "\""
	fmt.Println(url)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("error")
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error")
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(body))
}

func transact() {
	fmt.Print("Enter fromAddress: ")
	var fromAddress string
	fmt.Scanln(&fromAddress)

	fmt.Print("Enter toAddress: ")
	var toAddress string
	fmt.Scanln(&toAddress)

	fmt.Print("Enter numTokens: ")
	var numTokens string
	fmt.Scanln(&numTokens)

	fmt.Print("Enter sequence: ")
	var sequence string
	fmt.Scanln(&sequence)

	sign := GetSignatureTransactToken(fromAddress, toAddress, numTokens, sequence)

	url := "http://localhost:46657/broadcast_tx_commit?tx=\"transact," + fromAddress + "," +
		"" + toAddress + "," + numTokens + "," + sequence + "," + string(sign) + "\""

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("error")
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error")
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(url)

	fmt.Println(string(body))

}

func GetSignatureIssueToken(userAddress string, numTokens string, sequence string) string {
	private_key := readPrivateKey()

	data := map[string]string{
		"func":        "issueTokens",
		"userAddress": userAddress,
		"numTokens":   numTokens,
		"sequence":    sequence,
	}
	json_data, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err)
		fmt.Println("error in GetSignatureIssueToken- json.Marshal")
		os.Exit(1)
	}

	h := sha1.New()
	h.Write(json_data)
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	sha1_hash_byte := []byte(sha1_hash)

	sign := private_key.Sign(sha1_hash_byte)
	sign_bytes := sign.Bytes()

	sign_base64 := hex.EncodeToString(sign_bytes)

	return sign_base64

}

func GetSignatureTransactToken(fromAddress string, toAddress string, numTokens string, sequence string) string {
	private_key := readPrivateKey()

	data := map[string]string{
		"func":        "transact",
		"fromAddress": fromAddress,
		"toAddress":   toAddress,
		"numTokens":   numTokens,
		"sequence":    sequence,
	}
	json_data, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	h := sha1.New()
	h.Write(json_data)
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	sha1_hash_byte := []byte(sha1_hash)

	sign := private_key.Sign(sha1_hash_byte)
	sign_bytes := sign.Bytes()

	sign_base64 := hex.EncodeToString(sign_bytes)

	return sign_base64
}

func readPrivateKey() *crypto.PrivKeyEd25519 {
	keyEncoded, _ := ioutil.ReadFile("key")
	key := new(crypto.PrivKeyEd25519)
	block, _ := pem.Decode(keyEncoded)
	encodedPrivate := block.Bytes
	key.UnmarshalJSON(encodedPrivate)
	return key
}
