package service

import (
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

func (c *Client) Decshare(r *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point) ([]*pvss.PubVerShare, onet.ClientError) {
	// func (c *Client) Decshare(r *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) ([]abstract.Point, onet.ClientError) {

	decshareReq := &DecshareRequest{
		Roster:    r,
		H:         h,
		EncShares: encShares,
		EncProofs: encProofs,
	}
	if len(r.List) == 0 {
		log.Lvl3("Roster list is empty")
	}

	log.Lvl3("Roster length is", len(r.List))

	dst := r.List[0]
	log.Lvl3("Sending message to", dst)
	reply := &DecshareResponse{}
	err := c.SendProtobuf(dst, decshareReq, reply)
	if err != nil {
		return nil, err
	}
	log.Lvl3("Returning from Decshare")
	return reply.DecShares, nil
}
