package main

import (
	"os"
	"fmt"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"crypto/ecdsa"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"crypto/rand"
	"encoding/pem"
	"crypto/x509"
	
)

func main(){

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
	
	url := "http://localhost:46657/broadcast_tx_commit?tx=\"issueTokens," + userAddress + "," + numTokens + "," + sign + "," + sequence+"\""
	
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

func GetSignatureIssueToken(userAddress string, numTokens string, sequence string)string{
	private_key := readPrivateKey()

	data := map[string]string{
		"func": "issueTokens",
		"userAddress": userAddress,
		"numTokens": numTokens,
		"sequence": sequence,
	}
	json_data, err := json.Marshal(data)

	h := sha1.New()
	h.Write(json_data)
	sha1_hash := hex.EncodeToString(h.Sum(nil))

	r, s, err := ecdsa.Sign(rand.Reader, private_key, []byte(sha1_hash))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	
	signatureBigInt := new(big.Int)
	signatureBigInt.SetBytes(signature)
	
	signatureString := signatureBigInt.String()

	return signatureString
}

func readPrivateKey()*ecdsa.PrivateKey{
	keyEncoded, _ := ioutil.ReadFile("key")
	block, _ := pem.Decode(keyEncoded)
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}
