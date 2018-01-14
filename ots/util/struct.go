package util

// package ots

import (
	"github.com/dedis/cothority/skipchain"
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

type WriteTxnData struct {
	G          abstract.Point
	H          abstract.Point
	PublicKeys []abstract.Point
	EncShares  []*pvss.PubVerShare
	EncProofs  []abstract.Point
	HashEnc    []byte
	ReaderPk   abstract.Point
}

type OTSDecryptReqData struct {
	WriteTxnSBF  *skipchain.SkipBlockFix
	ReadTxnSBF   *skipchain.SkipBlockFix
	MerkleProof  *skipchain.BlockLink
	ACPublicKeys []abstract.Point
}

type ReencryptedShare struct {
	Index int
	Data  []byte
}
