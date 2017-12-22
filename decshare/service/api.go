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

func (c *Client) Decshare(r *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point, fwdLink *skipchain.BlockLink, scPubKeys []abstract.Point, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID, readBlkHdr *skipchain.SkipBlockFix) ([]*pvss.PubVerShare, onet.ClientError) {

	decshareReq := &DecshareRequest{
		Roster:     r,
		H:          h,
		EncShares:  encShares,
		EncProofs:  encProofs,
		FwdLink:    fwdLink,
		ScPubKeys:  scPubKeys,
		WriteHash:  writeHash,
		ReadHash:   readHash,
		ReadBlkHdr: readBlkHdr,
	}

	if len(r.List) == 0 {
		log.Lvl3("Roster list is empty")
	}

	log.Lvl3("Roster length is", len(r.List))

	//Random send
	idx := rand.Int() % len(r.List)
	// dst := r.RandomServerIdentity()
	dst := r.List[idx]
	decshareReq.RootIndex = idx

	log.Lvl3("Sending message to", dst)
	reply := &DecshareResponse{}
	err := c.SendProtobuf(dst, decshareReq, reply)
	if err != nil {
		return nil, err
	}
	log.Lvl3("Returning from Decshare")

	return reply.DecShares, nil
}
