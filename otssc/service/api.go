package service

import (
	"math/rand"

	"github.com/dedis/cothority/skipchain"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(ServiceName)}
}

func (c *Client) OTSDecrypt(r *onet.Roster, h abstract.Point, scPubKeys []abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point, fwdLink *skipchain.BlockLink, readBlkHdr *skipchain.SkipBlockFix, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID) ([]*pvss.PubVerShare, onet.ClientError) {

	decryptReq := &OTSDecryptReq{
		Roster:       r,
		H:            h,
		SCPublicKeys: scPubKeys,
		EncShares:    encShares,
		EncProofs:    encProofs,
		FwdLink:      fwdLink,
		ReadBlkHdr:   readBlkHdr,
		WriteHash:    writeHash,
		ReadHash:     readHash,
	}

	if len(r.List) == 0 {
		log.Lvl3("Roster list is empty")
	}

	log.Lvl3("Roster length is", len(r.List))

	//Random send
	idx := rand.Int() % len(r.List)
	// dst := r.RandomServerIdentity()
	dst := r.List[idx]
	decryptReq.RootIndex = idx

	log.Lvl3("Sending message to", dst)
	reply := &OTSDecryptResp{}
	err := c.SendProtobuf(dst, decryptReq, reply)
	if err != nil {
		return nil, err
	}
	log.Lvl3("Returning from OTSDecrpyt")

	return reply.DecShares, nil
}
