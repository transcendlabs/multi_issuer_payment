package multi_issuer_payment

import (
	"github.com/gods/maps/treemap"
	"github.com/tendermint/go-crypto"
)

type SmartCardIssuer struct {
	PublicKey       crypto.PubKey
	MinSequence     uint32
	SeenSequence    *treemap.Map
	MaxSeenSequence uint32
}

type SmartCardUser struct {
	Balance            uint64
	PublicKey          crypto.PubKey
	AutoReloadEnabled  bool
	AutoReloadValue    uint64
	AutoReloadSequence uint32
	MinSequence        uint32
	SeenSequence       *treemap.Map
	MaxSeenSequence    uint32
	Issuer             *SmartCardIssuer
}

/*
These are smart card topup stations- machines and people whom the issuer has franchised.
*/
type DelegatedSmartCardIssuer struct {
	PublicKey       crypto.PubKey
	MinSequence     uint32
	SeenSequence    *treemap.Map
	MaxSeenSequence uint32
}

type SmartCardProcessor struct {
	PublicKey       crypto.PubKey
	MinSequence     uint32
	SeenSequence    *treemap.Map
	MaxSeenSequence uint32
	Balances        []IssuerBalance
	//struct array used(and not map) because go-wire (used to encode data structure to bytes) doesn't support maps and recommend this way
}

type IssuerBalance struct {
	Issuer  *SmartCardIssuer
	Balance uint64
}

/*I thought of storing all SeenSequences
But it is not necessary for the time being
Let's go with one last_seen_sequence
I had it for a reason.
I wanted to store all sequences for a reason. But that would add additional complexity. SO, let's not store all sequences.
*/
