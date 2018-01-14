package protocol

import (
	"github.com/dedis/cothority_template/ots/util"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
)

// type ReencReply struct {
// 	K abstract.Point
// 	C abstract.Point
// }

type AnnounceDecrypt struct {
	DecReqData *util.OTSDecryptReqData
	Signature  *crypto.SchnorrSig
	RootIndex  int
}

// type AnnounceDecrypt struct {
// 	H            abstract.Point
// 	ACPublicKeys []abstract.Point
// 	EncShare     *pvss.PubVerShare
// 	EncProof     abstract.Point
// 	FwdLink      *skipchain.BlockLink
// 	ReadBlkHdr   *skipchain.SkipBlockFix
// 	WriteHash    skipchain.SkipBlockID
// 	ReadHash     skipchain.SkipBlockID
// 	Signature    *crypto.SchnorrSig
// }

type StructAnnounceDecrypt struct {
	*onet.TreeNode
	AnnounceDecrypt
}

type DecryptReply struct {
	DecShare *util.ReencryptedShare
	// DecShare ReencReply
	// DecShare *ReencReply
	// DecShare *pvss.PubVerShare
}

type StructDecryptReply struct {
	*onet.TreeNode
	DecryptReply
}
