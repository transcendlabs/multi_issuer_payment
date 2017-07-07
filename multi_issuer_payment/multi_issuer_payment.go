package multi_issuer_payment

import (
	"strings"
	"fmt"
	//"github.com/ror-shubham_2/multi_issuer_payment/multi_issuer_payment"
	"github.com/tendermint/merkleeyes/iavl"
	"github.com/tendermint/abci/types"
	"github.com/tendermint/tmlibs/merkle"
	cmn "github.com/tendermint/tmlibs/common"
	//"github.com/tendermint/go-crypto"
	wire "github.com/tendermint/go-wire"
	"strconv"
	"bytes"
	//"github.com/tendermint/go-crypto"
	//"crypto/elliptic"
	//"reflect"
	"crypto/ecdsa"
	//"crypto/md5"
	//"crypto/rand"
	"os"
	"crypto/x509"
	//"io"
	"io/ioutil"
	//"hash"
	"encoding/json"
	//"reflect"
	"math/big"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"github.com/tendermint/go-crypto"

)


type MultiIssuerPaymentApplication struct {
	types.BaseApplication
	userAccounts merkle.Tree
	processorAccounts merkle.Tree
}

func NewMultiIssuerPaymentApplication() *MultiIssuerPaymentApplication {
	userAccounts := iavl.NewIAVLTree(0, nil)
	processorAccounts := iavl.NewIAVLTree(0, nil)
	return &MultiIssuerPaymentApplication{userAccounts: userAccounts, processorAccounts: processorAccounts}
}



func (app *MultiIssuerPaymentApplication) CheckTx(tx []byte) types.Result {
	parts := strings.Split(string(tx), ",")
	if parts[0] == "issueTokens" {
		if len(parts) != 5 {
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format, format should be of form 'issueTokens,account,tokens,signature,sequence'"))
		} else {
			userAddress := string(parts[1])
			numTokens := parts[2]
			signature := parts[3]
			sequence := parts[4]

			sequenceUint64,_ := strconv.ParseUint(sequence,10,32)
			sequenceUint := uint32(sequenceUint64)


			verified := VerifySignatureIssueToken(userAddress, numTokens, sequence, signature)
			if !verified {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
			}


			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, userAddress)
			ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
			//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes
			//TODO check what to do if the account doesn't already exists


			if (sequenceUint != userAccount.MaxSeenSequence + 1) {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching. Sequence should be %x",userAccount.MaxSeenSequence+1))
			}

		}
	}else if parts[0] == "transact"{
        	if len(parts) != 6 {
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format, format should be of form 'transact,fromAccount,toAccount,tokens,signature,sequence'"))
		}else{
			fromAddress := string(parts[1])
			toAddress := string(parts[2])
			numTokens := parts[3]
			signature := parts[4]
			sequence := parts[5]

			sequenceUint64,_ := strconv.ParseUint(sequence,10,32)
			sequenceUint := uint32(sequenceUint64)

			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, fromAddress)
			ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
			//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes


			if (sequenceUint != userAccount.MaxSeenSequence + 1) {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching. Sequence should be %x",userAccount.MaxSeenSequence+1))
			}

			verified := VerifySignatureTransact(fromAddress, toAddress, numTokens, sequence, signature)
			if !verified {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
			}

        }
    }
	return types.OK
}
func (app *MultiIssuerPaymentApplication) DeliverTx(tx []byte) types.Result {
	parts := strings.Split(string(tx), ",")
	if parts[0] == "issueTokens" {
		if len(parts) != 5 {
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format, format should be of form 'account,tokens,signature,sequence'"))
		} else {
			userAddress := string(parts[1])
			numTokens := parts[2]
			signature := parts[3]
			sequence := parts[4]
			//signature := GetSignatureIssueToken(userAddress,numTokens , sequence_str)

			sequenceUint64,_ := strconv.ParseUint(sequence,10,32)
			sequenceUint := uint32(sequenceUint64)


			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, userAddress)
			ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
			//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes


			if (sequenceUint != userAccount.MaxSeenSequence + 1) {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching. Sequence should be %x",userAccount.MaxSeenSequence+1))
			}


			verified := VerifySignatureIssueToken(userAddress, numTokens, sequence, signature)
			if verified {
				issueTokens(app, userAddress, numTokens,sequence, signature)
			} else{
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
			}

			userAccount = &SmartCardUser{}	//couldn't use from userAccount from above as userAccount is modified in issueTokens
			_, userAccountBytes = userAccountDetails(app, userAddress)
			ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
			//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

			userAccount.MaxSeenSequence += 1
			fmt.Println("maxseensequence", userAccount.MaxSeenSequence)

			buf := wire.BinaryBytes(userAccount) //encoded to []byte
			app.userAccounts.Set([]byte(userAddress),buf)



		}
	}else if parts[0] == "transact"{
        	if len(parts) != 6 {
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format, format should be of form 'transact,account,tokens,signature,sequence'"))
		}else{
			fromAddress := string(parts[1])
			toAddress := string(parts[2])
			numTokens := parts[3]
			signature := parts[4]
			sequence := parts[5]

			sequenceUint64,_ := strconv.ParseUint(sequence,10,32)
			sequenceUint := uint32(sequenceUint64)

			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, fromAddress)
			ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
			//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes


			if (sequenceUint != userAccount.MaxSeenSequence + 1) {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching. Sequence should be %x",userAccount.MaxSeenSequence+1))
			}


			verified := VerifySignatureTransact(fromAddress,toAddress, numTokens, sequence, signature)
			if verified {
		        	transact(app, fromAddress,toAddress,numTokens,signature,sequence)	
            		}else{
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
           		}
           		
           		userAccount = &SmartCardUser{}	//couldn't use from userAccount from above as userAccount is modified in transact()
			_, userAccountBytes = userAccountDetails(app, fromAddress)
			ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
			//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

			userAccount.MaxSeenSequence += 1
			fmt.Println("maxseensequence", userAccount.MaxSeenSequence)

			buf := wire.BinaryBytes(userAccount) //encoded to []byte
			app.userAccounts.Set([]byte(fromAddress),buf)

        }
    }

	return types.OK
}


//func issueTokens(issuerAddress, userAddress, numTokens, signature){
func issueTokens(app *MultiIssuerPaymentApplication, userAddress string, numTokens string,sequence string,signature string){

	exists, userAccountBytes := userAccountDetails(app, userAddress)

	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)

	if exists{
		pubKey := *ReadPublicKeyTypeCrypto()
		issuer := &SmartCardIssuer{PublicKey:pubKey}
	
		userAccount := &SmartCardUser{Issuer: issuer}

		ReadBinaryBytes(userAccountBytes, userAccount) //decoded user_account_bytes to user_account(of type SmartCardUser)
		//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

		
		userAccount.Balance += numTokensUint64
		fmt.Println("Account = ",userAddress, "Balance = ", userAccount.Balance)

		buf := wire.BinaryBytes(userAccount)   //encoded to []byte
		app.userAccounts.Set([]byte(userAddress),buf)
	}else{
		userAccount := &SmartCardUser{Balance:0}
		userAccount.Balance = numTokensUint64
		fmt.Println("Account  = " ,userAddress, "Balance = ", userAccount.Balance)

		buf := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(userAddress),buf)
	}


}

func transact(app *MultiIssuerPaymentApplication, fromAddress string,toAddress string,numTokens string,signature string,sequence string) {
	_, processorAccountBytes := processorAccountDetails(app, toAddress)
	exists, userAccountBytes := userAccountDetails(app, fromAddress)
	numTokensUint64, _ := strconv.ParseUint(numTokens, 10, 64)
	if exists {
		processorAccount := &SmartCardProcessor{}
		ReadBinaryBytes(processorAccountBytes, processorAccount)

		//dummy issuer here, just for data filling
		pubKey := *ReadPublicKeyTypeCrypto()
		issuer := &SmartCardIssuer{PublicKey:pubKey}
		userAccount := &SmartCardUser{Issuer: issuer}
		ReadBinaryBytes(userAccountBytes, userAccount)
		

		//to find balance for given issuer by searching in struct array and adding balance to it
		check := false
		for i, balance := range processorAccount.Balance {
			if *(balance.Issuer) == *issuer{
				processorAccount.Balance[i].Balance += numTokensUint64
				check = true
			}
		}
		if !check {
			processorAccount.Balance = append(processorAccount.Balance, IssuerBalance{Issuer: issuer,Balance: numTokensUint64})
		}
		fmt.Println("processor",processorAccount)
		
		userAccount.Balance -= numTokensUint64
		fmt.Println("Account = ",fromAddress, "Balance = ", userAccount.Balance)

		buf_processor := wire.BinaryBytes(processorAccount) //encoded to []byte
		app.processorAccounts.Set([]byte(toAddress),buf_processor)
		
		buf_user := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(fromAddress),buf_user)
		
		

	}else{
		//same as above
		//if this is executed it should be error should be shown
		processorAccount := &SmartCardProcessor{}
		ReadBinaryBytes(processorAccountBytes, processorAccount)

		//dummy issuer here, just for data filling
		pubKey := *ReadPublicKeyTypeCrypto()
		issuer := &SmartCardIssuer{PublicKey:pubKey}
		userAccount := &SmartCardUser{Issuer: issuer}
		ReadBinaryBytes(userAccountBytes, userAccount)
		

		//to find balance for given issuer by searching in struct array and adding balance to it
		check := false
		for i, balance := range processorAccount.Balance {
			fmt.Println("processor_loop",balance)
			if *(balance.Issuer) == *issuer{
				processorAccount.Balance[i].Balance += numTokensUint64
				check = true
			}
		}
		if !check {
			processorAccount.Balance = append(processorAccount.Balance, IssuerBalance{Issuer: issuer,Balance: numTokensUint64})
		}
		fmt.Println("processor",processorAccount.Balance)
		
		userAccount.Balance -= numTokensUint64
		fmt.Println("Account = ",fromAddress, "Balance = ", userAccount.Balance)

		buf_processor := wire.BinaryBytes(processorAccount) //encoded to []byte
		app.processorAccounts.Set([]byte(toAddress),buf_processor)
		
		buf_user := wire.BinaryBytes(userAccount) //encoded to []byte
		app.userAccounts.Set([]byte(fromAddress),buf_user)
	}
}

func userAccountDetails(app *MultiIssuerPaymentApplication, userAddress string) (bool, []byte){
	_, userAccounts, exists := app.userAccounts.Get([]byte(userAddress))
	return exists, userAccounts
}

func processorAccountDetails(app *MultiIssuerPaymentApplication, processorAddress string) (bool, []byte){
	_, processorAccounts, exists := app.processorAccounts.Get([]byte(processorAddress))
	return exists, processorAccounts
}


func ReadBinaryBytes(d []byte, ptr interface{}) error {
	//somehow function implemented in util.go in package go-wire was giving weird results so implemented here.
	//Only difference is use of ReadBinary() in place of ReadBinaryPtr
	r, n, err := bytes.NewBuffer(d), new(int), new(error)
	wire.ReadBinary(ptr, r, len(d), n, err)
	return *err
}



func VerifySignatureIssueToken(userAddress string, numTokens string, sequence string, signature string)bool{
	public_key := readPublicKey()

	signBigInt := new(big.Int)
	signBigInt.SetString(signature,10)
	signBytes := signBigInt.Bytes()

	if len(signBytes) != 64{
		return false
	}else{

		data := map[string]string{
			"func": "issueTokens",
			"userAddress": userAddress,
			"numTokens": numTokens,
			"sequence": sequence,
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

func VerifySignatureTransact(fromAddress string, toAddress string, numTokens string, sequence string, signature string)bool{
	public_key := readPublicKey()

	signBigInt := new(big.Int)
	signBigInt.SetString(signature,10)
	signBytes := signBigInt.Bytes()

	if len(signBytes) != 64{
		return false
	}else{

		data := map[string]string{
			"func": "transact",
			"fromAddress": fromAddress,
			"toAddress": toAddress,
			"numTokens": numTokens,
			"sequence": sequence,
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


func readPublicKey()*ecdsa.PublicKey{
	pubKeyEncoded, _ := ioutil.ReadFile("/home/shubh/key.pub")
	blockPub, _ := pem.Decode(pubKeyEncoded)
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}

func ReadPublicKeyTypeCrypto()*crypto.PubKey{
	//remove later
	//used because ReadBinaryBytes doesn't accept public key in ecdsa.PublicKey format so crypto.PubKey needed to be used
	pubKeyEncoded, _ := ioutil.ReadFile("/home/shubh/key_1.pub")
	key := new(crypto.PubKey)
	blockPub, _ := pem.Decode(pubKeyEncoded)
	x509EncodedPub := blockPub.Bytes
	key.UnmarshalJSON(x509EncodedPub)

	return key
}

//TODO implement get_query or info
//TODO print all issuer from processor_account
