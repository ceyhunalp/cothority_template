package protocol

import (
	"errors"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

var Name = "Keypoll"

func init() {
	network.RegisterMessage(Announce{})
	network.RegisterMessage(Reply{})
	onet.GlobalProtocolRegister(Name, NewProtocol)
}

type KeypollChannelStruct struct {
	*onet.TreeNodeInstance
	Message string
	// PrivateKeys chan []abstract.Scalar
	PublicKeys      chan []abstract.Point
	ChannelAnnounce chan StructAnnounce
	ChannelReply    chan []StructReply
}

func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	KeypollChannels := &KeypollChannelStruct{
		TreeNodeInstance: n,
		PublicKeys:       make(chan []abstract.Point),
		// PrivateKeys: make(chan []abstract.Scalar),
	}
	err := KeypollChannels.RegisterChannel(&KeypollChannels.ChannelAnnounce)
	if err != nil {
		return nil, errors.New("couldn't register announcement-channel: " + err.Error())
	}
	err = KeypollChannels.RegisterChannel(&KeypollChannels.ChannelReply)
	if err != nil {
		return nil, errors.New("couldn't register reply-channel: " + err.Error())
	}
	return KeypollChannels, nil
}

func (p *KeypollChannelStruct) Start() error {
	log.Lvl3("Starting KeypollChannels")
	p.ChannelAnnounce <- StructAnnounce{nil, Announce{"Keypoll is here"}}
	return nil
}

func (p *KeypollChannelStruct) Dispatch() error {
	// var keys []abstract.Scalar
	var keys []abstract.Point
	announcement := <-p.ChannelAnnounce
	if p.IsLeaf() {
		// keys = append(keys, p.Private())
		keys = append(keys, p.Public())
		err := p.SendTo(p.Parent(), &Reply{keys})
		if err != nil {
			log.Error(p.Info(), "Failed to send reply to", p.Parent().Name(), err)
		}
		return nil
	}

	for _, c := range p.Children() {
		err := p.SendTo(c, &announcement.Announce)
		if err != nil {
			log.Error(p.Info(), "failed to send to", c.Name(), err)
		}
	}

	reply := <-p.ChannelReply

	for _, c := range reply {
		for _, key := range c.PublicKey {
			// for _, key := range c.PrivateKey {
			keys = append(keys, key)
		}
	}

	log.Lvl3(p.ServerIdentity().Address, "is done with total of", len(keys))

	if !p.IsRoot() {
		log.Lvl3("Sending to parent")
		keys = append(keys, p.Public())
		// keys = append(keys, p.Private())
		err := p.SendTo(p.Parent(), &Reply{keys})
		if err != nil {
			log.Error(p.Info(), "failed to reply to", p.Parent().Name(), err)
		}
	} else {
		keys = append(keys, p.Public())
		// keys = append(keys, p.Private())
		log.Lvl3("Root-node is done - nbr of keys:", len(keys))
		// p.PrivateKeys <- keys
		p.PublicKeys <- keys
	}
	return nil
}
