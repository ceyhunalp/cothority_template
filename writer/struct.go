package main

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/crypto.v0/share/pvss"
)

type DataPVSS struct {
	Suite      abstract.Suite
	G          abstract.Point
	H          abstract.Point
	NumTrustee int
	Threshold  int
	Secret     abstract.Scalar
	PublicKeys []abstract.Point
	EncShares  []*pvss.PubVerShare
	EncProofs  []abstract.Point
	CommitPoly *share.PubPoly
}

type WriteTransactionData struct {
	EncShares []*pvss.PubVerShare
	EncProofs []abstract.Point
	PubKeys   []abstract.Point
	G         abstract.Point
	H         abstract.Point
	HashEnc   []byte
}
