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


//TODO work on signature
//func issueTokens(issuerAddress, userAddress, numTokens, signature){
func issueTokens(app *MultiIssuerPaymentApplication, userAddress string, numTokens uint64){
	
	exists, user_account_bytes := accountDetails(app, userAddress)
	
	if exists{
		user_account := &SmartCardUser{}
		

		ReadBinaryBytes(user_account_bytes, user_account) //decoded user_account_bytes to user_account(of type SmartCardUser)
		//used ReadBinaryBytes(locally implemented) and not wire.ReadBinaryBytes
		
		
		user_account.Balance += numTokens
		
		
		buf := wire.BinaryBytes(user_account)   //encoded to []byte
		app.user_accounts.Set([]byte(userAddress),buf)
	}else{
		user_account := &SmartCardUser{Balance:0}
		user_account.Balance = numTokens
		
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
		u,_ := strconv.ParseUint(parts[1], 10, 64)
		issueTokens(app, string(parts[0]), u)
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



