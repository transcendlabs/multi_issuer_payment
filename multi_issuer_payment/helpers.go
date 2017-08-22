package multi_issuer_payment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	wire "github.com/tendermint/go-wire"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
)

//func issueTokens(issuerAddress, userAddress, numTokens, signature){
func issueTokens(app *MultiIssuerPaymentApplication,
	userAddress string,
	numTokens string,
	sequence string,
	signature string,
) {
	exists, userAccountBytes := accountDetails(app, userAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)

	if exists {
		userAccount := &SmartCardUser{}
		readBinaryBytes(userAccountBytes, userAccount)
		//decoded user_account_bytes to user_account(of type SmartCardUser)
		//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

		userAccount.Balance += numTokensUint64
		fmt.Println("Account = ", userAddress, "Balance = ", userAccount.Balance)

		buf := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress), buf)
	} else {
		userAccount := &SmartCardUser{Balance: 0}
		userAccount.Balance = numTokensUint64
		fmt.Println("Account  = ", userAddress, "Balance = ", userAccount.Balance)

		buf := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress), buf)
	}
}

func transact(app *MultiIssuerPaymentApplication,
	fromAddress string,
	toAddress string,
	numTokens string,
	sequence string,
	signature string,
) {
	exists_from, fromAccountBytes := accountDetails(app, fromAddress)
	exists_to, toAccountBytes := accountDetails(app, toAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)
	if exists_to && exists_from {
		fromAccount := &SmartCardUser{}
		toAccount := &SmartCardUser{}

		readBinaryBytes(fromAccountBytes, fromAccount)
		readBinaryBytes(toAccountBytes, toAccount)
		//decoded user_account_bytes to user_account(of type SmartCardUser)
		//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes
		fmt.Println("balance = ", fromAccount.Balance)
		toAccount.Balance += numTokensUint64
		fromAccount.Balance -= numTokensUint64
		fmt.Println("Account = ", fromAddress, "Balance = ", fromAccount.Balance)
		fmt.Println("balance = ", fromAccount.Balance)
		fmt.Println("Account = ", toAddress, "Balance = ", toAccount.Balance)

		buf_from := wire.BinaryBytes(fromAccount) //encoded to []byte
		app.userAccounts.Set([]byte(fromAddress), buf_from)
		buf_to := wire.BinaryBytes(toAccount) //encoded to []byte
		app.userAccounts.Set([]byte(toAddress), buf_to)

	} else if exists_from {
		fromAccount := &SmartCardUser{}
		toAccount := &SmartCardUser{Balance: 0}

		readBinaryBytes(fromAccountBytes, fromAccount)

		fmt.Println("balance = ", fromAccount.Balance)
		toAccount.Balance += numTokensUint64
		fromAccount.Balance -= numTokensUint64
		fmt.Println("Account = ", fromAddress, "Balance = ", fromAccount.Balance)
		fmt.Println("balance = ", fromAccount.Balance)
		fmt.Println("Account = ", toAddress, "Balance = ", toAccount.Balance)

		buf_from := wire.BinaryBytes(fromAccount) //encoded to []byte
		app.userAccounts.Set([]byte(fromAddress), buf_from)
		buf_to := wire.BinaryBytes(fromAccount) //encoded to []byte
		app.userAccounts.Set([]byte(toAddress), buf_to)
	} else {
		//TODO error it out
		fmt.Println("account doesn't exist")
	}
}

func hasSufficientBalance(app *MultiIssuerPaymentApplication, userAddress string, numTokens string) bool {
	exists, userAccountBytes := accountDetails(app, userAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)
	if exists {
		userAccount := &SmartCardUser{}
		readBinaryBytes(userAccountBytes, userAccount)
		//decoded user_account_bytes to user_account(of type SmartCardUser)
		//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

		if (userAccount.Balance) >= numTokensUint64 {
			return true
		}
	}
	return false
}

func accountDetails(app *MultiIssuerPaymentApplication, userAddress string) (bool, []byte) {
	_, userAccounts, exists := app.userAccounts.Get([]byte(userAddress))
	return exists, userAccounts
}

func readBinaryBytes(d []byte, ptr interface{}) error {
	//somehow function implemented in util.go in package go-wire was giving weird results so implemented here.
	//Only difference is use of ReadBinary() in place of ReadBinaryPtr
	r, n, err := bytes.NewBuffer(d), new(int), new(error)
	wire.ReadBinary(ptr, r, len(d), n, err)
	return *err
}

func verifySignatureIssue(userAddress string, numTokens string, sequence string, signature string) bool {
	public_key := readPublicKey()

	signBigInt := new(big.Int)
	signBigInt.SetString(signature, 10)
	signBytes := signBigInt.Bytes()

	if len(signBytes) != 64 {
		return false
	} else {

		data := map[string]string{
			"func":        "issueTokens",
			"userAddress": userAddress,
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

		r := new(big.Int)
		r.SetBytes(signBytes[0:32])
		s := new(big.Int)
		s.SetBytes(signBytes[32:64])

		verifyStatus := ecdsa.Verify(public_key, []byte(sha1_hash), r, s)

		return verifyStatus
	}
}

func verifySignatureTransact(fromAddress string, toAddress string, numTokens string, sequence string, signature string) bool {
	public_key := readPublicKey()

	signBigInt := new(big.Int)
	signBigInt.SetString(signature, 10)
	signBytes := signBigInt.Bytes()

	if len(signBytes) != 64 {
		return false
	} else {

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

		r := new(big.Int)
		r.SetBytes(signBytes[0:32])
		s := new(big.Int)
		s.SetBytes(signBytes[32:64])

		verifyStatus := ecdsa.Verify(public_key, []byte(sha1_hash), r, s)

		return verifyStatus
	}
}

func readPublicKey() *ecdsa.PublicKey {
	pubKeyEncoded, _ := ioutil.ReadFile("/home/shubh/key.pub")
	//TODO catch IOerror here
	blockPub, _ := pem.Decode(pubKeyEncoded)
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}
