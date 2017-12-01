package protocol

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
)

type Announce struct {
	Message string
}

type StructAnnounce struct {
	*onet.TreeNode
	Announce
}

type Reply struct {
	// PrivateKey []abstract.Scalar
	PublicKey []abstract.Point
}

type StructReply struct {
	*onet.TreeNode
	Reply
}
