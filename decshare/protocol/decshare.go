package protocol

import (
	"errors"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

var Name = "Decshare"

func init() {
	network.RegisterMessage(AnnounceDecrypt{})
	network.RegisterMessage(DecryptReply{})
	onet.GlobalProtocolRegister(Name, NewProtocol)
}

type DecshareChannelStruct struct {
	*onet.TreeNodeInstance
	Message         string
	DecShares       chan []*pvss.PubVerShare
	ChannelAnnounce chan StructAnnounceDecrypt
	ChannelReply    chan []StructDecryptReply
	H               abstract.Point
	EncShares       []*pvss.PubVerShare
	EncProofs       []abstract.Point
}

func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	DecshareChannels := &DecshareChannelStruct{
		TreeNodeInstance: n,
		DecShares:        make(chan []*pvss.PubVerShare),
	}
	err := DecshareChannels.RegisterChannel(&DecshareChannels.ChannelAnnounce)
	if err != nil {
		return nil, errors.New("couldn't register announcement-channel: " + err.Error())
	}
	err = DecshareChannels.RegisterChannel(&DecshareChannels.ChannelReply)
	if err != nil {
		return nil, errors.New("couldn't register reply-channel: " + err.Error())
	}
	return DecshareChannels, nil
}

func (p *DecshareChannelStruct) Start() error {
	log.Lvl3("Starting DecshareChannels")
	p.ChannelAnnounce <- StructAnnounceDecrypt{nil, AnnounceDecrypt{
		H:         p.H,
		EncShares: p.EncShares,
		EncProofs: p.EncProofs,
	}}
	return nil
}

func (p *DecshareChannelStruct) Dispatch() error {
	var decShares []*pvss.PubVerShare
	var tmp *pvss.PubVerShare
	var err error

	idx := p.Index()
	announcement := <-p.ChannelAnnounce

	if p.IsLeaf() {
		tmp, err = pvss.DecShare(network.Suite, announcement.H, p.Public(), announcement.EncProofs[idx], p.Private(), announcement.EncShares[idx])
		log.Info("Error is", err)
		if err != nil {
			log.Error(p.Info(), "Failed to decrypt share", p.Parent().Name(), err)
		}
		decShares = append(decShares, tmp)
		err = p.SendTo(p.Parent(), &DecryptReply{decShares})
		if err != nil {
			log.Error(p.Info(), "Failed to send reply to", p.Parent().Name(), err)
		}
		return nil
	}

	for _, c := range p.Children() {
		err := p.SendTo(c, &announcement.AnnounceDecrypt)
		if err != nil {
			log.Error(p.Info(), "failed to send to", c.Name(), err)
		}
	}

	reply := <-p.ChannelReply

	for _, c := range reply {
		for _, tmp := range c.DecShare {
			decShares = append(decShares, tmp)
		}
	}

	log.Lvl3(p.ServerIdentity().Address, "is done with total of", len(decShares))

	tmp, err = pvss.DecShare(network.Suite, announcement.H, p.Public(), announcement.EncProofs[idx], p.Private(), announcement.EncShares[idx])
	log.Info("Error is", err)
	if err != nil {
		log.Error(p.Info(), "Failed to decrypt share", p.Parent().Name(), err)
	}
	decShares = append(decShares, tmp)

	if !p.IsRoot() {
		log.Lvl3("Sending to parent")
		err := p.SendTo(p.Parent(), &DecryptReply{decShares})
		if err != nil {
			log.Error(p.Info(), "failed to reply to", p.Parent().Name(), err)
		}
	} else {
		log.Lvl3("Root-node is done - nbr of keys:", len(decShares))
		p.DecShares <- decShares
	}
	return nil
}
