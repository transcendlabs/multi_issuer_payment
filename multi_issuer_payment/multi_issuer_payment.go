package multi_issuer_payment

import (
	"fmt"
	"github.com/tendermint/abci/types"
	wire "github.com/tendermint/go-wire"
	"github.com/tendermint/merkleeyes/iavl"
	cmn "github.com/tendermint/tmlibs/common"
	"github.com/tendermint/tmlibs/merkle"
	"strconv"
	"strings"
)

type MultiIssuerPaymentApplication struct {
	types.BaseApplication
	userAccounts      merkle.Tree
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
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format," +
				"format should be of form " +
				"'issueTokens,account,tokens,signature,sequence'"))
		} else {
			userAddress := string(parts[1])
			numTokens := parts[2]
			sequence := parts[3]
			signature := parts[4]

			sequenceUint64, _ := strconv.ParseUint(sequence, 10, 32)
			sequenceUint := uint32(sequenceUint64)

			verified := verifySignatureIssue(userAddress, numTokens, sequence, signature)
			if !verified {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
			}

			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, userAddress)
			readBinaryBytes(userAccountBytes, userAccount)
			//decoded user_account_bytes to user_account(of type SmartCardUser)
			//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes
			//TODO check what to do if the account doesn't already exists

			if sequenceUint != userAccount.MaxSeenSequence+1 {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching."+
					" Sequence should be %x", userAccount.MaxSeenSequence+1))
			}

		}
	} else if parts[0] == "transact" {
		if len(parts) != 6 {
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format," +
				" format should be of form 'transact," + "fromAccount" +
				"toAccount,tokens,signature,sequence'"))
		} else {
			fromAddress := string(parts[1])
			toAddress := string(parts[2])
			numTokens := parts[3]
			sequence := parts[4]
			signature := parts[5]

			sequenceUint64, _ := strconv.ParseUint(sequence, 10, 32)
			sequenceUint := uint32(sequenceUint64)

			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, fromAddress)
			readBinaryBytes(userAccountBytes, userAccount)
			//decoded user_account_bytes to user_account(of type SmartCardUser)
			//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

			if sequenceUint != userAccount.MaxSeenSequence+1 {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching."+
					" Sequence should be %x", userAccount.MaxSeenSequence+1))
			}

			verified := verifySignatureTransact(fromAddress, toAddress, numTokens, sequence, signature)
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
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format, format" +
				" should be of form 'account,tokens,signature,sequence'"))
		} else {
			userAddress := string(parts[1])
			numTokens := parts[2]
			sequence := parts[3]
			signature := parts[4]
			//signature := GetSignatureIssueToken(userAddress,numTokens , sequence_str)

			sequenceUint64, _ := strconv.ParseUint(sequence, 10, 32)
			sequenceUint := uint32(sequenceUint64)

			userAccount := &SmartCardUser{}
			_, userAccountBytes := userAccountDetails(app, userAddress)
			readBinaryBytes(userAccountBytes, userAccount)
			//decoded user_account_bytes to user_account(of type SmartCardUser)
			//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

			if sequenceUint != userAccount.MaxSeenSequence+1 {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching."+
					" Sequence should be %x", userAccount.MaxSeenSequence+1))
			}

			verified := verifySignatureIssue(userAddress, numTokens, sequence, signature)
			if verified {
				issueTokens(app, userAddress, numTokens, sequence, signature)
			} else {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
			}

			userAccount = &SmartCardUser{}
			//couldn't use from above as userAccount is modified in issueTokens
			_, userAccountBytes = userAccountDetails(app, userAddress)
			readBinaryBytes(userAccountBytes, userAccount)
			//decoded user_account_bytes to user_account(of type SmartCardUser)
			//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

			userAccount.MaxSeenSequence += 1
			fmt.Println("maxseensequence", userAccount.MaxSeenSequence)

			buf := wire.BinaryBytes(userAccount) //encoded to []byte
			app.userAccounts.Set([]byte(userAddress), buf)

		}
	} else if parts[0] == "transact" {
		if len(parts) != 6 {
			return types.ErrEncodingError.SetLog(cmn.Fmt("Not valid format," +
				" format should be of form 'issueTokens,fromAccount, toAccount, tokens,signature,sequence'"))
		} else {
			fromAddress := string(parts[1])
			toAddress := string(parts[2])
			numTokens := parts[3]
			sequence := parts[4]
			signature := parts[5]

			sequenceUint64, _ := strconv.ParseUint(sequence, 10, 32)
			sequenceUint := uint32(sequenceUint64)

			fromAccount := &SmartCardUser{}
			_, fromAccountBytes := userAccountDetails(app, fromAddress)
			readBinaryBytes(fromAccountBytes, fromAccount)
			//decoded user_account_bytes to user_account(of type SmartCardUser)
			//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes

			if sequenceUint != fromAccount.MaxSeenSequence+1 {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Sequence not matching."+
					" Sequence should be %x", fromAccount.MaxSeenSequence+1))
			}

			verified := verifySignatureTransact(fromAddress, toAddress, numTokens, sequence, signature)
			hasBalance := hasSufficientBalance(app, fromAddress, numTokens)
			if !verified {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Signature not verified"))
			}
			if !hasBalance {
				return types.ErrEncodingError.SetLog(cmn.Fmt("Not Sufficient Balance."))
			}

			transact(app, fromAddress, toAddress, numTokens, signature, sequence)

			fromAccount = &SmartCardUser{}
			//couldn't use from above as userAccount is modified in issueTokens
			_, fromAccountBytes = userAccountDetails(app, fromAddress)
			readBinaryBytes(fromAccountBytes, fromAccount)
			//decoded user_account_bytes to user_account(of type SmartCardUser)
			//used readBinaryBytes(locally implemented) and not wire.ReadBinaryBytes
			fromAccount.MaxSeenSequence += 1
			fmt.Println("maxseensequence", fromAccount.MaxSeenSequence)

			buf := wire.BinaryBytes(fromAccount) //encoded to []byte
			app.userAccounts.Set([]byte(fromAddress), buf)

		}
	}

	return types.OK
}
