package main

import "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"

// Node represents a participant holding a key share.
type Node struct {
	id   int
	data keygen.LocalPartySaveData
}

func NewNode(id int) *Node {
	return &Node{id: id}
}

func (n *Node) KeyData() keygen.LocalPartySaveData {
	return n.data
}
