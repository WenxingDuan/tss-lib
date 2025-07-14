package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func runKeygen(participants, threshold int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	pIDs := tss.GenerateTestPartyIDs(participants)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*keygen.LocalParty, 0, participants)
	errCh := make(chan *tss.Error, participants)
	outCh := make(chan tss.Message, participants)
	endCh := make(chan *keygen.LocalPartySaveData, participants)

	for i := 0; i < participants; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], participants, threshold)
		P := keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	updater := test.SharedPartyUpdater

	var ended int32
	keys := make([]keygen.LocalPartySaveData, 0, participants)
keygenLoop:
	for {
		select {
		case err := <-errCh:
			return nil, nil, fmt.Errorf("keygen error: %v", err)
		case msg := <-outCh:
			if dest := msg.GetTo(); dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				go updater(parties[dest[0].Index], msg, errCh)
			}
		case save := <-endCh:
			atomic.AddInt32(&ended, 1)
			keys = append(keys, *save)
			if atomic.LoadInt32(&ended) == int32(participants) {
				break keygenLoop
			}
		}
	}
	// pIDs is already sorted by GenerateTestPartyIDs
	return keys, pIDs, nil
}

func runSigning(keys []keygen.LocalPartySaveData, pIDs tss.SortedPartyIDs, msg []byte, threshold int) (*common.SignatureData, error) {
	participants := len(keys)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*signing.LocalParty, 0, participants)
	errCh := make(chan *tss.Error, participants)
	outCh := make(chan tss.Message, participants)
	endCh := make(chan *common.SignatureData, participants)

	for i := 0; i < participants; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], participants, threshold)
		P := signing.NewLocalParty(new(big.Int).SetBytes(msg), params, keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	updater := test.SharedPartyUpdater

	var ended int32
	var sig *common.SignatureData
signingLoop:
	for {
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("signing error: %v", err)
		case msg := <-outCh:
			if dest := msg.GetTo(); dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				go updater(parties[dest[0].Index], msg, errCh)
			}
		case sd := <-endCh:
			atomic.AddInt32(&ended, 1)
			sig = sd
			if atomic.LoadInt32(&ended) == int32(threshold+1) {
				break signingLoop
			}
		}
	}
	return sig, nil
}

func main() {
	participants := 3
	threshold := 1

	keys, pids, err := runKeygen(participants, threshold)
	if err != nil {
		panic(err)
	}

	// Example message: hash of "hello eth"
	h := sha256.Sum256([]byte("hello eth"))

	sig, err := runSigning(keys, pids, h[:], threshold)
	if err != nil {
		panic(err)
	}

	r := new(big.Int).SetBytes(sig.R)
	s := new(big.Int).SetBytes(sig.S)
	fmt.Printf("Signature (r,s): %s %s\n", r.String(), s.String())

	// Verify using standard ecdsa
	pk := ecdsa.PublicKey{Curve: tss.S256(), X: keys[0].ECDSAPub.X(), Y: keys[0].ECDSAPub.Y()}
	ok := ecdsa.Verify(&pk, h[:], r, s)
	fmt.Printf("ECDSA Verify: %v\n", ok)

	fmt.Printf("Signature hex r: %s\n", hex.EncodeToString(sig.R))
	fmt.Printf("Signature hex s: %s\n", hex.EncodeToString(sig.S))
}
