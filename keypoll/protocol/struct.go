package protocol

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/crypto.v0/abstract"
)

type Announce struct {
	Message string
}

type StructAnnounce struct {
	*onet.TreeNode
	Announce
}

type Reply struct {
	PublicKey []abstract.Point
}

type StructReply struct {
	*onet.TreeNode
	Reply
}
