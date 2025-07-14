package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

func main() {
	participants := 3
	threshold := 1

	nodes := make([]*Node, participants)
	for i := 0; i < participants; i++ {
		nodes[i] = NewNode(i)
	}

	agg := NewAggregator(nodes, threshold)

	if err := agg.KeyGen(); err != nil {
		panic(err)
	}

	msgHash := sha256.Sum256([]byte("hello eth"))

	sig, err := agg.Sign(msgHash[:])
	if err != nil {
		panic(err)
	}

	r := new(big.Int).SetBytes(sig.R)
	s := new(big.Int).SetBytes(sig.S)
	fmt.Printf("Signature (r,s): %s %s\n", r.String(), s.String())

	pk := ecdsa.PublicKey{Curve: tss.S256(), X: nodes[0].data.ECDSAPub.X(), Y: nodes[0].data.ECDSAPub.Y()}
	ok := ecdsa.Verify(&pk, msgHash[:], r, s)
	fmt.Printf("ECDSA Verify: %v\n", ok)
	fmt.Printf("Signature hex r: %s\n", hex.EncodeToString(sig.R))
	fmt.Printf("Signature hex s: %s\n", hex.EncodeToString(sig.S))
}
