package main

import (
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Aggregator coordinates threshold key generation and signing among nodes.
type Aggregator struct {
	nodes     []*Node
	pids      tss.SortedPartyIDs
	threshold int
}

func NewAggregator(nodes []*Node, threshold int) *Aggregator {
	return &Aggregator{nodes: nodes, threshold: threshold}
}

// KeyGen runs the distributed key generation protocol and stores the key shares
// on each node.
func (a *Aggregator) KeyGen() error {
	participants := len(a.nodes)
	pIDs := tss.GenerateTestPartyIDs(participants)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*keygen.LocalParty, participants)
	errCh := make(chan *tss.Error, participants)
	outCh := make(chan tss.Message, participants)
	endCh := make(chan *keygen.LocalPartySaveData, participants)

	for i := 0; i < participants; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], participants, a.threshold)
		parties[i] = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		go func(p *keygen.LocalParty) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(parties[i])
	}

	updater := test.SharedPartyUpdater

	var ended int32
keygenLoop:
	for {
		select {
		case err := <-errCh:
			return fmt.Errorf("keygen error: %v", err)
		case msg := <-outCh:
			if dest := msg.GetTo(); dest == nil {
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(p, msg, errCh)
				}
			} else {
				go updater(parties[dest[0].Index], msg, errCh)
			}
		case save := <-endCh:
			idx := -1
			for i, id := range pIDs {
				if id.KeyInt().Cmp(save.ShareID) == 0 {
					idx = i
					break
				}
			}
			if idx < 0 {
				return fmt.Errorf("unable to match save data to party id")
			}
			a.nodes[idx].data = *save
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(participants) {
				a.pids = pIDs
				break keygenLoop
			}
		}
	}
	return nil
}

// Sign runs the threshold signing protocol for the provided message bytes.
func (a *Aggregator) Sign(msg []byte) (*common.SignatureData, error) {
	participants := len(a.nodes)
	p2pCtx := tss.NewPeerContext(a.pids)

	parties := make([]*signing.LocalParty, participants)
	errCh := make(chan *tss.Error, participants)
	outCh := make(chan tss.Message, participants)
	endCh := make(chan *common.SignatureData, participants)

	for i := 0; i < participants; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, a.pids[i], participants, a.threshold)
		parties[i] = signing.NewLocalParty(new(big.Int).SetBytes(msg), params, a.nodes[i].data, outCh, endCh).(*signing.LocalParty)
		go func(p *signing.LocalParty) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(parties[i])
	}

	updater := test.SharedPartyUpdater

	var ended int32
	var sig *common.SignatureData
signLoop:
	for {
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("signing error: %v", err)
		case msg := <-outCh:
			if dest := msg.GetTo(); dest == nil {
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(p, msg, errCh)
				}
			} else {
				go updater(parties[dest[0].Index], msg, errCh)
			}
		case sd := <-endCh:
			atomic.AddInt32(&ended, 1)
			sig = sd
			if atomic.LoadInt32(&ended) == int32(a.threshold+1) {
				break signLoop
			}
		}
	}
	return sig, nil
}
