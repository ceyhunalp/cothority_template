package ots

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
)

type DataPVSS struct {
	NumTrustee int
	Threshold  int
	Suite      abstract.Suite
	G          abstract.Point
	H          abstract.Point
	Secret     abstract.Scalar
	PublicKeys []abstract.Point
	EncShares  []*pvss.PubVerShare
	EncProofs  []abstract.Point
	// CommitPoly *share.PubPoly
}

type WriteTransactionData struct {
	G          abstract.Point
	H          abstract.Point
	PublicKeys []abstract.Point
	EncShares  []*pvss.PubVerShare
	EncProofs  []abstract.Point
	HashEnc    []byte
}
