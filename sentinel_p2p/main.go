package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// IOCMessage represents an IOC shared over P2P network
type IOCMessage struct {
	IOCHash          string    `json:"ioc_hash"`
	SourceCommitment string    `json:"source_commitment"`
	Proof            string    `json:"proof"`
	Metadata         string    `json:"metadata"`
	Timestamp        time.Time `json:"timestamp"`
}

// P2PNode represents a node in the threat intelligence network
type P2PNode struct {
	ID       string
	Peers    []string
	IOCCache map[string]IOCMessage
}

// NewP2PNode creates a new P2P node
func NewP2PNode(id string) *P2PNode {
	return &P2PNode{
		ID:       id,
		Peers:    make([]string, 0),
		IOCCache: make(map[string]IOCMessage),
	}
}

// Connect connects to a peer
func (n *P2PNode) Connect(peerID string) error {
	for _, p := range n.Peers {
		if p == peerID {
			return fmt.Errorf("already connected to %s", peerID)
		}
	}
	
	n.Peers = append(n.Peers, peerID)
	log.Printf("[%s] Connected to peer: %s", n.ID, peerID)
	return nil
}

// BroadcastIOC broadcasts an IOC to all peers (gossip protocol)
func (n *P2PNode) BroadcastIOC(ioc IOCMessage) error {
	// Store in local cache
	n.IOCCache[ioc.IOCHash] = ioc
	
	log.Printf("[%s] Broadcasting IOC: %s to %d peers", n.ID, ioc.IOCHash, len(n.Peers))
	
	// In production: Send to all connected peers via libp2p
	// Here: Simulate broadcast
	for _, peer := range n.Peers {
		log.Printf("[%s] -> [%s] IOC: %s", n.ID, peer, ioc.IOCHash)
	}
	
	return nil
}

// ReceiveIOC receives an IOC from a peer
func (n *P2PNode) ReceiveIOC(ioc IOCMessage, fromPeer string) error {
	// Check if already in cache
	if _, exists := n.IOCCache[ioc.IOCHash]; exists {
		log.Printf("[%s] IOC already in cache: %s", n.ID, ioc.IOCHash)
		return nil
	}
	
	// Store in cache
	n.IOCCache[ioc.IOCHash] = ioc
	log.Printf("[%s] Received IOC from [%s]: %s", n.ID, fromPeer, ioc.IOCHash)
	
	// Gossip to other peers (except sender)
	for _, peer := range n.Peers {
		if peer != fromPeer {
			log.Printf("[%s] Gossiping IOC to [%s]: %s", n.ID, peer, ioc.IOCHash)
		}
	}
	
	return nil
}

// QueryIOC queries local cache for an IOC
func (n *P2PNode) QueryIOC(iocHash string) (IOCMessage, bool) {
	ioc, exists := n.IOCCache[iocHash]
	return ioc, exists
}

// GetStats returns node statistics
func (n *P2PNode) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"node_id":     n.ID,
		"peer_count":  len(n.Peers),
		"ioc_count":   len(n.IOCCache),
		"peers":       n.Peers,
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sentinel_p2p <node_id>")
		os.Exit(1)
	}
	
	nodeID := os.Args[1]
	
	// Create node
	node := NewP2PNode(nodeID)
	log.Printf("Starting P2P node: %s", nodeID)
	
	// Simulate network
	ctx := context.Background()
	_ = ctx
	
	// Connect to peers (simulated)
	if nodeID == "node1" {
		node.Connect("node2")
		node.Connect("node3")
	} else if nodeID == "node2" {
		node.Connect("node1")
		node.Connect("node3")
	} else if nodeID == "node3" {
		node.Connect("node1")
		node.Connect("node2")
	}
	
	// Broadcast test IOC
	testIOC := IOCMessage{
		IOCHash:          "a1b2c3d4e5f6...",
		SourceCommitment: "commitment123...",
		Proof:            "proof456...",
		Metadata:         `{"type":"ip","severity":"high"}`,
		Timestamp:        time.Now(),
	}
	
	node.BroadcastIOC(testIOC)
	
	// Print stats
	stats := node.GetStats()
	statsJSON, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Printf("\nNode Stats:\n%s\n", statsJSON)
	
	log.Printf("P2P node %s running...", nodeID)
}
