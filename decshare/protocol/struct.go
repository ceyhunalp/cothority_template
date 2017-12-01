package protocol

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
)

type Prep struct {
	H         abstract.Point
	EncShares []*pvss.PubVerShare
	EncProofs []abstract.Point
}

type StructPrep struct {
	*onet.TreeNode
	Prep
}

type Resp struct {
	DecShare []*pvss.PubVerShare
}

type StructResp struct {
	*onet.TreeNode
	Resp
}
