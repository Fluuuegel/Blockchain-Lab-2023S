package main

import (
	"crypto/sha256"
	"errors"
	"bytes"
)

// MerkleTree represent a Merkle tree
type MerkleTree struct {
	RootNode *MerkleNode
	Leaf     [][]byte
}

// MerkleNode represent a Merkle tree node
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// NewMerkleTree creates a new Merkle tree from a sequence of data
// implement
func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []*MerkleNode

	if len(data) == 0 {
		return &MerkleTree{}
	}
	
  // 如果节点数是奇数，复制最后一个节点一次
	if len(data)%2 != 0 {
		data = append(data, data[len(data)-1])
	}

	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, node)
	}

	// 循环建立父节点
	for i := 0; i < len(data)/2; i++ {
		var level []*MerkleNode
		for j := 0; j < len(nodes); j += 2 {
			node := NewMerkleNode(nodes[j], nodes[j + 1], nil)
			level = append(level, node)
		}
		nodes = level
	}

	return &MerkleTree{nodes[0], data}
}

// NewMerkleNode creates a new Merkle tree node
// implement
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}
	var hash [32]byte
	
	// 分情况讨论，如果是叶子节点，直接计算hash，如果是非叶子节点，计算左右子节点的hash
	if data == nil {
		if left != nil && right != nil {
			hash = sha256.Sum256(append(left.Data, right.Data...))
		} else if left != nil {
			hash = sha256.Sum256(left.Data)
		} else if right != nil {
			hash = sha256.Sum256(right.Data)
		}
	} else {
		hash = sha256.Sum256(data)
	}

	node.Left = left
	node.Right = right
	node.Data = hash[:]
	return &node
}

func (t *MerkleTree) SPVproof(index int) ([][]byte, error) {
	
	if index < 0 || index > len(t.Leaf)-1 {
		return nil, errors.New("index out of range")
	}
	proof := make([][]byte, 0)
	length := 1
	left := 0
	node := t.RootNode
	
	for node.Right != nil {
		length *= 2
		node = node.Right
	}
	node = t.RootNode

	for length > 1 {
		length = length / 2
		if index >= left+length {
			proof = append(proof, node.Left.Data)
			node = node.Right
			left += length
		} else {
			proof = append(proof, node.Right.Data)
			node = node.Left
		}
	}

	for i := 0; i < len(proof)/2; i++ {
		j := len(proof) - 1 - i
		proof[i], proof[j] = proof[j], proof[i]
	}
	return proof, nil
}

func (t *MerkleTree) VerifyProof(index int, path [][]byte) (bool, error) {

	if index < 0 || index >= len(t.Leaf) {
		return false, errors.New("index out of range")
	}
	
	hash := sha256.Sum256(t.Leaf[index])
	
	for _, p := range path {
		if index%2 == 0 {
			hash = sha256.Sum256(append(hash[:], p...))
		} else {
			hash = sha256.Sum256(append(p, hash[:]...))
		}
		index /= 2
	}
	
	return bytes.Equal(hash[:], t.RootNode.Data), nil
	
}
