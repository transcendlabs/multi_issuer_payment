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
	//"crypto/ecdsa"
	wire "github.com/tendermint/go-wire"
	"strconv"
	"bytes"
	//"github.com/tendermint/go-crypto"


)


type MultiIssuerPaymentApplication struct {
	types.BaseApplication
	user_accounts merkle.Tree
}

func NewMultiIssuerPaymentApplication() *MultiIssuerPaymentApplication {
	user_accounts := iavl.NewIAVLTree(0, nil)
	return &MultiIssuerPaymentApplication{user_accounts: user_accounts}
}


	
//func issueTokens(issuerAddress, userAddress, numTokens, signature){
func issueTokens(app *MultiIssuerPaymentApplication, userAddress string, numTokens string,sequence string,signture){

	verified := VerifySignature(userAddress, numTokens, sequence)
	
	exists, user_account_bytes := accountDetails(app, userAddress)
	
	numTokens_uint64,_ := strconv.ParseUint(numTokens, 10, 64)
	
	
	if exists{
		user_account := &SmartCardUser{}
		

		ReadBinaryBytes(user_account_bytes, user_account) //decoded user_account_bytes to user_account(of type SmartCardUser)
		//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes
		
		
		user_account.Balance += numTokens_uint64
		
		
		buf := wire.BinaryBytes(user_account)   //encoded to []byte
		app.user_accounts.Set([]byte(userAddress),buf)
	}else{
		user_account := &SmartCardUser{Balance:0}
		user_account.Balance = numTokens_uint64
		
		buf := wire.BinaryBytes(user_account) //encoded to []byte
		app.user_accounts.Set([]byte(userAddress),buf)
	}
	
	
}

func accountDetails(app *MultiIssuerPaymentApplication, userAddress string) (bool, []byte){
	_, user_accounts, exists := app.user_accounts.Get([]byte(userAddress))
	return exists, user_accounts 
}
	
func (app *MultiIssuerPaymentApplication) CheckTx(tx []byte) types.Result {
	return types.OK
}

func (app *MultiIssuerPaymentApplication) DeliverTx(tx []byte) types.Result {
	

	parts := strings.Split(string(tx), "=")
	if len(parts) == 2 {
		userAddress := string(parts[0])
		numTokens := parts[1]
		//numTokens,_ := strconv.ParseUint(parts[1], 10, 64)
		signature := GetSignatureIssueToken(userAddress,numTokens , "1")
		//TODO change "1" to sequence variable
		issueTokens(app, userAddress, numTokens, signature)
	} else {
		return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format, format should be of form 'account=tokens'")) 
	}
	return types.OK
}

func ReadBinaryBytes(d []byte, ptr interface{}) error {
	//somehow function implemented in util.go in package go-wire was giving weird results so implemented here.
	//Only difference is use of ReadBinary() in place of ReadBinaryPtr
	r, n, err := bytes.NewBuffer(d), new(int), new(error)
	wire.ReadBinary(ptr, r, len(d), n, err)
	return *err
}

func GetSignatureIssueToken(userAddress string, numTokens string, sequence string)[]uint8{
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
 	
 	return signature
}


func VerifySignature(userAddress string, numTokens uint64, sequence string, signature []uint8)bool{
	public_key := readPublicKey()
	
	
	numTokens_string :=strconv.FormatUint(numTokens, 10)
	data := map[string]string{
		"func": "issueTokens",
		"userAddress": userAddress,
		"numTokens": numTokens_string,
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
	r.SetBytes(signature[0:32])
	s := new(big.Int)
	s.SetBytes(signature[32:64])
	
	verifyStatus := ecdsa.Verify(public_key, []byte(sha1_hash), r, s)
	
	return verifyStatus
}





