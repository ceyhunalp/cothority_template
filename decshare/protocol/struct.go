package protocol

import (
	"github.com/dedis/cothority/skipchain"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
)

type AnnounceDecrypt struct {
	H          abstract.Point
	EncShare   *pvss.PubVerShare
	EncProof   abstract.Point
	FwdLink    *skipchain.BlockLink
	ScPubKeys  []abstract.Point
	WriteHash  skipchain.SkipBlockID
	ReadHash   skipchain.SkipBlockID
	ReadBlkHdr *skipchain.SkipBlockFix
}

type StructAnnounceDecrypt struct {
	*onet.TreeNode
	AnnounceDecrypt
}

type DecryptReply struct {
	DecShare *pvss.PubVerShare
}

type StructDecryptReply struct {
	*onet.TreeNode
	DecryptReply
}
