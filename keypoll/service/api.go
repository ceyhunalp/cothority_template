package service

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(ServiceName)}
}

func (c *Client) Keypoll(r *onet.Roster) ([]abstract.Point, onet.ClientError) {
	// func (c *Client) Keypoll(r *onet.Roster) ([]abstract.Scalar, onet.ClientError) {
	keypollReq := &KeypollRequest{
		Roster: r,
	}
	if len(r.List) == 0 {
		log.Lvl3("Roster list is empty")
	}

	log.Lvl3("Roster length is", len(r.List))

	dst := r.List[0]
	log.Lvl3("Sending message to", dst)
	reply := &KeypollResponse{}
	err := c.SendProtobuf(dst, keypollReq, reply)
	if err != nil {
		return nil, err
	}
	log.Lvl3("Returning from Keypoll")
	// return reply.PrivateKeys, nil
	return reply.PublicKeys, nil
}
