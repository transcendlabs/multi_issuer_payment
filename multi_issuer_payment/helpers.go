package multi_issuer_payment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	//"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/tendermint/go-crypto"
	wire "github.com/tendermint/go-wire"
	"io/ioutil"
	"os"
	//"reflect"
	"strconv"
)

//func issueTokens(issuerAddress, userAddress, numTokens, signature){
func issueTokens(app *MultiIssuerPaymentApplication,
	userAddress string,
	numTokens string,
	sequence string,
	signature string,
) {
	exists, userAccountBytes := userAccountDetails(app, userAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)

	if exists {
		pubKey := *readPublicKeyTypeCrypto()
		issuer := &SmartCardIssuer{PublicKey: pubKey}

		userAccount := &SmartCardUser{Issuer: issuer}
		//added issuer to SmartCardUser
		//later it needs to be modified(Issuer should be set only once I think)
		err := readBinaryBytes(userAccountBytes, userAccount)
		if err != nil {
			fmt.Println("err in helpers.issue.if.readBinaryBytes")
			fmt.Println(err)
			os.Exit(1)
		}
		//decoded user_account_bytes to user_account(of type SmartCardUser)
		//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

		userAccount.Balance += numTokensUint64
		fmt.Println("Account = ", userAddress, "Balance = ", userAccount.Balance, "User = ", userAccount)

		buf := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress), buf)
	} else {
		pubKey := *readPublicKeyTypeCrypto()
		issuer := &SmartCardIssuer{PublicKey: pubKey}

		userAccount := &SmartCardUser{Balance: 0, Issuer: issuer}
		//added issuer to SmartCardUser
		//later it needs to be modified(Issuer should be set only once I think)

		userAccount.Balance = numTokensUint64
		fmt.Println("Account  = ", userAddress, "Balance = ", userAccount.Balance, "User = ", userAccount)

		buf := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress), buf)
	}
}

func transact(app *MultiIssuerPaymentApplication,
	userAddress string,
	processorAddress string,
	numTokens string,
	sequence string,
	signature string,
) {
	exists_user, userAccountBytes := userAccountDetails(app, userAddress)
	exists_processor, processorAccountBytes := processorAccountDetails(app, processorAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)
	if exists_processor && exists_user {
		userAccount := &SmartCardUser{}
		processorAccount := &SmartCardProcessor{}

		err := readBinaryBytes(userAccountBytes, userAccount)
		err = readBinaryBytes(processorAccountBytes, processorAccount)
		if err != nil {
			fmt.Println("err in helpers.transact.if.readBinaryBytes")
			fmt.Println(err)
			os.Exit(1)
		}
		//decoded user_account_bytes to user_account(of type SmartCardUser)
		//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

		//to find balance for given issuer by searching in struct array and adding balance to it
		issuerExists := false

		issuer := userAccount.Issuer
		for i, balance := range processorAccount.Balances {
			if *(balance.Issuer) == *issuer {
				processorAccount.Balances[i].Balance += numTokensUint64
				issuerExists = true
			}
		}
		if !issuerExists {
			//add issuer in processor account if not exist
			processorAccount.Balances = append(processorAccount.Balances, IssuerBalance{Issuer: issuer, Balance: numTokensUint64})
		}

		userAccount.Balance -= numTokensUint64
		fmt.Println("Account = ", userAddress, "Balance = ", userAccount.Balance, "User = ", userAccount)
		fmt.Println("Account = ", processorAddress, "Balances = ", processorAccount.Balances, "User = ", processorAccount)

		buf_from := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress), buf_from)
		buf_to := wire.BinaryBytes(processorAccount) //encoded to []byte
		app.processorAccounts.Set([]byte(processorAddress), buf_to)

	} else if exists_user {
		makeDummyProcessor(app, processorAddress)
		_, processorAccountBytes = processorAccountDetails(app, processorAddress)
		userAccount := &SmartCardUser{}

		processorAccount := &SmartCardProcessor{}

		err := readBinaryBytes(processorAccountBytes, processorAccount)
		err = readBinaryBytes(userAccountBytes, userAccount)
		if err != nil {
			fmt.Println("err in helpers.transact.else if.readBinaryBytes")
			fmt.Println(err)
			os.Exit(1)
		}

		//to find balance for given issuer by searching in struct array and adding balance to it
		issuerExists := false

		issuer := userAccount.Issuer
		for i, balance := range processorAccount.Balances {
			if *(balance.Issuer) == *issuer {
				processorAccount.Balances[i].Balance += numTokensUint64
				issuerExists = true
			}
		}
		if !issuerExists {
			//add issuer in processor account if not exist
			processorAccount.Balances = append(processorAccount.Balances,
				IssuerBalance{Issuer: issuer, Balance: numTokensUint64})
		}

		userAccount.Balance -= numTokensUint64
		fmt.Println("Account = ", userAddress, "Balance = ", userAccount.Balance, "User = ", userAccount)
		fmt.Println("Account = ", processorAddress, "Balances = ", processorAccount.Balances, "User = ", processorAccount)

		buf_from := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress), buf_from)
		buf_to := wire.BinaryBytes(processorAccount) //encoded to []byte
		app.processorAccounts.Set([]byte(processorAddress), buf_to)
	} else {
		//TODO error it out
		fmt.Println("account doesn't exist")
	}
}

//TODO remove it later
func makeDummyProcessor(app *MultiIssuerPaymentApplication, processorAddress string) {
	pubKey := *readPublicKeyTypeCrypto()
	processorAccount := &SmartCardProcessor{PublicKey: pubKey}

	buf := wire.BinaryBytes(processorAccount) //encoded to []byte
	processorAccount2 := &SmartCardProcessor{}
	err := readBinaryBytes(buf, processorAccount2)
	if err != nil {
		fmt.Println("err in helpers.makeDummyProcessor.readBinaryBytes")
		fmt.Println(err)
		os.Exit(1)
	}
	app.processorAccounts.Set([]byte(processorAddress), buf)

}

func hasSufficientBalance(app *MultiIssuerPaymentApplication, userAddress string, numTokens string) bool {
	exists, userAccountBytes := userAccountDetails(app, userAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)
	if exists {
		userAccount := &SmartCardUser{}
		err := readBinaryBytes(userAccountBytes, userAccount)

		if err != nil {
			fmt.Println("err in helpers.hasSufficientBalance.readBinaryBytes")
			fmt.Println(err)
			os.Exit(1)
		}
		//decoded user_account_bytes to user_account(of type SmartCardUser)
		//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

		if (userAccount.Balance) >= numTokensUint64 {
			return true
		}
	}
	return false
}

func userAccountDetails(app *MultiIssuerPaymentApplication, userAddress string) (bool, []byte) {
	_, userAccounts, exists := app.userAccounts.Get([]byte(userAddress))
	return exists, userAccounts
}

func processorAccountDetails(app *MultiIssuerPaymentApplication, processorAddress string) (bool, []byte) {
	_, processorAccounts, exists := app.processorAccounts.Get([]byte(processorAddress))
	return exists, processorAccounts
}

func readBinaryBytes(d []byte, ptr interface{}) error {
	//somehow function implemented in util.go in package go-wire was giving weird results so implemented here.
	//Only difference is use of ReadBinary() in place of ReadBinaryPtr()
	r, n, err := bytes.NewBuffer(d), new(int), new(error)
	wire.ReadBinary(ptr, r, len(d), n, err)
	return *err
}

func verifySignatureIssue(userAddress string, numTokens string, sequence string, signature string) bool {
	public_key := readPublicKeyTypeCrypto()

	signature_bytes, err := hex.DecodeString(signature)
	if err != nil {
		fmt.Println("err in helpers.verifySignatureIssue.signature_bytes")
		fmt.Println(err)
		os.Exit(1)
	}

	signature_final, err := crypto.SignatureFromBytes(signature_bytes)

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
	sha1_hash_bytes := []byte(sha1_hash)
	verifyStatus := public_key.VerifyBytes(sha1_hash_bytes, signature_final)

	return verifyStatus
}

func verifySignatureTransact(fromAddress string, toAddress string, numTokens string, sequence string, signature string) bool {
	public_key := readPublicKeyTypeCrypto()
	signature_bytes, err := hex.DecodeString(signature)
	if err != nil {
		fmt.Println("err in helpers.verifySignatureTransact.signature_bytes")
		fmt.Println(err)
		os.Exit(1)
	}

	signature_final, err := crypto.SignatureFromBytes(signature_bytes)

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
	sha1_hash_bytes := []byte(sha1_hash)

	verifyStatus := public_key.VerifyBytes(sha1_hash_bytes, signature_final)

	return verifyStatus
}

func readPublicKey() *ecdsa.PublicKey {
	pubKeyEncoded, _ := ioutil.ReadFile("key.pub")
	//TODO catch IOerror here
	blockPub, _ := pem.Decode(pubKeyEncoded)
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}

func readPublicKeyTypeCrypto() *crypto.PubKey {
	//remove later
	//used because ReadBinaryBytes doesn't accept public key in ecdsa.PublicKey format so crypto.PubKey needed to be used
	pubKeyEncoded, _ := ioutil.ReadFile("key.pub")
	//TODO catch io error here
	key := new(crypto.PubKey)
	blockPub, _ := pem.Decode(pubKeyEncoded)

	x509EncodedPub := blockPub.Bytes
	key.UnmarshalJSON(x509EncodedPub)

	return key
}
