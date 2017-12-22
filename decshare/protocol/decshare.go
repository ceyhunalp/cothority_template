package protocol

import (
	"errors"

	ocs "github.com/dedis/onchain-secrets"

	"github.com/dedis/cothority/skipchain"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/cosi"
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

type ProtocolPVSSDecrypt struct {
	*onet.TreeNodeInstance
	DecShares       chan []*pvss.PubVerShare
	ChannelAnnounce chan StructAnnounceDecrypt
	ChannelReply    chan []StructDecryptReply
	H               abstract.Point
	EncShares       []*pvss.PubVerShare
	EncProofs       []abstract.Point
	FwdLink         *skipchain.BlockLink
	ScPubKeys       []abstract.Point
	WriteHash       skipchain.SkipBlockID
	ReadHash        skipchain.SkipBlockID
	ReadBlkHdr      *skipchain.SkipBlockFix
	RootIndex       int
}

func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	PVSSDecrypt := &ProtocolPVSSDecrypt{
		TreeNodeInstance: n,
		DecShares:        make(chan []*pvss.PubVerShare),
	}
	err := PVSSDecrypt.RegisterChannel(&PVSSDecrypt.ChannelAnnounce)
	if err != nil {
		return nil, errors.New("couldn't register announcement-channel: " + err.Error())
	}
	err = PVSSDecrypt.RegisterChannel(&PVSSDecrypt.ChannelReply)
	if err != nil {
		return nil, errors.New("couldn't register reply-channel: " + err.Error())
	}
	return PVSSDecrypt, nil
}

func (p *ProtocolPVSSDecrypt) Start() error {
	log.Lvl3("Starting PVSSDecrypt")

	for _, c := range p.Children() {
		idx := c.RosterIndex
		if idx <= p.RootIndex {
			idx--
		}

		err := p.SendTo(c, &AnnounceDecrypt{
			H:          p.H,
			EncShare:   p.EncShares[idx],
			EncProof:   p.EncProofs[idx],
			FwdLink:    p.FwdLink,
			ScPubKeys:  p.ScPubKeys,
			ReadHash:   p.ReadHash,
			WriteHash:  p.WriteHash,
			ReadBlkHdr: p.ReadBlkHdr,
		})
		if err != nil {
			log.Error(p.Info(), "failed to send to", c.Name(), err)
		}
	}

	return nil
}

func (p *ProtocolPVSSDecrypt) Dispatch() error {

	if p.IsLeaf() {
		announcement := <-p.ChannelAnnounce
		validSignErr := verifyDecryptionRequest(announcement.FwdLink, announcement.ScPubKeys, announcement.WriteHash, announcement.ReadHash, announcement.ReadBlkHdr)
		if validSignErr != nil {
			log.Error(p.Info(), "Failed to verify forward link", validSignErr)
			return nil
		}
		ds, err := pvss.DecShare(network.Suite, announcement.H, p.Public(), announcement.EncProof, p.Private(), announcement.EncShare)
		// log.Info("Error is", err)
		if err != nil {
			log.Error(p.Info(), "Failed to decrypt share", p.Parent().Name(), err)
		}
		err = p.SendTo(p.Parent(), &DecryptReply{ds})
		if err != nil {
			log.Error(p.Info(), "Failed to send reply to", p.Parent().Name(), err)
		}
		return nil
	}

	var decShares []*pvss.PubVerShare
	idx := p.RootIndex
	reply := <-p.ChannelReply

	for _, c := range reply {
		decShares = append(decShares, c.DecryptReply.DecShare)
	}

	validSignErr := verifyDecryptionRequest(p.FwdLink, p.ScPubKeys, p.WriteHash, p.ReadHash, p.ReadBlkHdr)
	if validSignErr != nil {
		log.Error(p.Info(), "Failed to verify forward link", validSignErr)
		return nil
	}
	ds, err := pvss.DecShare(network.Suite, p.H, p.Public(), p.EncProofs[idx], p.Private(), p.EncShares[idx])
	// log.Info("Error is", err)
	if err != nil {
		log.Error(p.Info(), "Failed to decrypt share", p.Parent().Name(), err)
	}

	log.Lvl3(p.ServerIdentity().Address, "is done with total of", len(decShares))

	decShares = append(decShares, ds)
	p.DecShares <- decShares
	return nil
}

func verifyDecryptionRequest(bl *skipchain.BlockLink, publics []abstract.Point, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID, readBlkHdr *skipchain.SkipBlockFix) error {

	if len(bl.Signature) == 0 {
		return errors.New("No signature present" + log.Stack())
	}

	hc := bl.Hash.Equal(readHash)

	if !hc {
		log.Lvl3("Forward link hash does not match read transaction hash")
		return errors.New("Forward link hash does not match read transaction hash")
	}

	log.Lvl3("Forward link hash matches read transaction hash")

	signErr := cosi.VerifySignature(network.Suite, publics, bl.Hash, bl.Signature)

	if signErr != nil {
		return signErr
	}

	readBlkHash := readBlkHdr.CalculateHash()
	_, tmp, _ := network.Unmarshal(readBlkHdr.Data)
	readBlk := tmp.(*ocs.DataOCS).Read

	hc = readBlkHash.Equal(readHash)

	if !hc {
		log.Lvl3("Hash in read block header not valid")
		return errors.New("Hash in read block header not valid")
	}

	log.Lvl3("Valid hash in read block header")

	hc = readBlk.DataID.Equal(writeHash)
	if !hc {
		log.Lvl3("Invalid write block hash in the read block")
		return errors.New("Invalid write block hash in the read block")
	}

	return nil
}
