package protocol

import (
	"crypto/sha256"
	"errors"

	"github.com/dedis/cothority_template/ots/util"
	ocs "github.com/dedis/onchain-secrets"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/cosi"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

var Name = "otssc"

func init() {
	network.RegisterMessage(AnnounceDecrypt{})
	network.RegisterMessage(DecryptReply{})
	network.RegisterMessage(&util.OTSDecryptReqData{})
	network.RegisterMessage(&util.DecryptedShare{})
	network.RegisterMessage(&pvss.PubVerShare{})
	onet.GlobalProtocolRegister(Name, NewProtocol)
}

type OTSDecrypt struct {
	*onet.TreeNodeInstance
	ChannelAnnounce chan StructAnnounceDecrypt
	ChannelReply    chan []StructDecryptReply
	DecShares       chan []*util.DecryptedShare
	DecReqData      *util.OTSDecryptReqData
	Signature       *crypto.SchnorrSig
	RootIndex       int
}

func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	otsDecrypt := &OTSDecrypt{
		TreeNodeInstance: n,
		DecShares:        make(chan []*util.DecryptedShare),
	}
	// err := otsDecrypt.RegisterChannelLength(&otsDecrypt.ChannelAnnounce, 2000)
	err := otsDecrypt.RegisterChannel(&otsDecrypt.ChannelAnnounce)

	if err != nil {
		return nil, errors.New("couldn't register announcement-channel: " + err.Error())
	}
	// err = otsDecrypt.RegisterChannelLength(&otsDecrypt.ChannelReply, 2000)
	err = otsDecrypt.RegisterChannel(&otsDecrypt.ChannelReply)

	if err != nil {
		return nil, errors.New("couldn't register reply-channel: " + err.Error())
	}
	return otsDecrypt, nil
}

func (p *OTSDecrypt) Start() error {
	log.Lvl3("Starting OTSDecrypt")
	for _, c := range p.Children() {

		// log.Info("In OTSSC:", *p.Signature)
		err := p.SendTo(c, &AnnounceDecrypt{
			DecReqData: p.DecReqData,
			Signature:  p.Signature,
			RootIndex:  p.RootIndex,
		})

		if err != nil {
			log.Error(p.Info(), "failed to send to", c.Name(), err)
		}
	}
	return nil
}

func (p *OTSDecrypt) Dispatch() error {
	if p.IsLeaf() {
		announcement := <-p.ChannelAnnounce
		writeTxnData, sigErr := verifyDecryptionRequest(announcement.DecReqData, announcement.Signature)
		if sigErr != nil {
			return sigErr
		}

		idx := p.Index()
		if idx <= announcement.RootIndex {
			idx--
		}

		// binKey, err := writeTxnData.ReaderPk.MarshalBinary()
		// if err != nil {
		// 	return err
		// }
		// tmpHash := sha256.Sum256(binKey)
		// labelHash := tmpHash[:]
		// h, _ := network.Suite.Point().Pick(nil, network.Suite.Cipher(labelHash))

		h, err := util.CreatePointH(network.Suite, writeTxnData.ReaderPk)
		if err != nil {
			log.Error(p.Info(), "Failed to generate point h", p.Name(), err)
			return err
		}

		ds := &util.DecryptedShare{
			Index: p.Index(),
		}

		tempSh, err := pvss.DecShare(network.Suite, h, p.Public(), writeTxnData.EncProofs[idx], p.Private(), writeTxnData.EncShares[idx])

		// tempSh, err := pvss.DecShare(network.Suite, writeTxnData.H, p.Public(), writeTxnData.EncProofs[idx], p.Private(), writeTxnData.EncShares[idx])

		if err != nil {
			log.Error(p.Info(), "Failed to decrypt share", p.Name(), err)
			ds.Data = []byte{}
		} else {
			reencSh := reencryptShare(tempSh, writeTxnData.ReaderPk, p.Private())
			ds.Data = reencSh
		}

		err = p.SendTo(p.Parent(), &DecryptReply{ds})
		if err != nil {
			log.Error(p.Info(), "Failed to send reply to", p.Parent().Name(), err)
			return err
		}
		return nil
	}

	var decShares []*util.DecryptedShare
	idx := p.RootIndex
	reply := <-p.ChannelReply

	for _, c := range reply {
		decShares = append(decShares, c.DecryptReply.DecShare)
	}

	writeTxnData, sigErr := verifyDecryptionRequest(p.DecReqData, p.Signature)
	if sigErr != nil {
		return sigErr
	}

	h, err := util.CreatePointH(network.Suite, writeTxnData.ReaderPk)
	if err != nil {
		log.Error(p.Info(), "Failed to generate point h", p.Name(), err)
		return err
	}
	// binKey, err := writeTxnData.ReaderPk.MarshalBinary()
	// if err != nil {
	// 	return err
	// }
	// tmpHash := sha256.Sum256(binKey)
	// labelHash := tmpHash[:]
	// h, _ := network.Suite.Point().Pick(nil, network.Suite.Cipher(labelHash))

	ds := &util.DecryptedShare{
		Index: p.Index(),
	}

	tempSh, err := pvss.DecShare(network.Suite, h, p.Public(), writeTxnData.EncProofs[idx], p.Private(), writeTxnData.EncShares[idx])

	// tempSh, err := pvss.DecShare(network.Suite, writeTxnData.H, p.Public(), writeTxnData.EncProofs[idx], p.Private(), writeTxnData.EncShares[idx])

	if err != nil {
		log.Error(p.Info(), "Failed to decrypt share", p.Name(), err)
		ds.Data = []byte{}
	} else {
		reencSh := reencryptShare(tempSh, writeTxnData.ReaderPk, p.Private())
		ds.Data = reencSh
	}

	decShares = append(decShares, ds)

	log.Lvl3(p.ServerIdentity().Address, "is done with total of", len(decShares))
	p.DecShares <- decShares
	return nil
}

func reencryptShare(ds *pvss.PubVerShare, rPubKey abstract.Point, privKey abstract.Scalar) []byte {

	msg, err := network.Marshal(ds)
	if err != nil {
		log.Errorf("Failed to marshall: %v", err)
		return nil
	}

	shSec, err := network.Suite.Point().Mul(rPubKey, privKey).MarshalBinary()
	if err != nil {
		log.Errorf("MarshalBinary failed: %v", err)
		return nil
	}
	tempSymKey := sha256.Sum256(shSec)
	symKey := tempSymKey[:]
	cipher := network.Suite.Cipher(symKey)
	reencShare := cipher.Seal(nil, msg)
	return reencShare
}

func verifyDecryptionRequest(decReqData *util.OTSDecryptReqData, sig *crypto.SchnorrSig) (*util.WriteTxnData, error) {

	_, tmp, err := network.Unmarshal(decReqData.WriteTxnSBF.Data)
	if err != nil {
		log.Errorf("Unmarshal failed: %v", err)
		return nil, err
	}
	writeTxn := tmp.(*ocs.DataOCS).WriteTxn.Data

	_, tmp, err = network.Unmarshal(decReqData.ReadTxnSBF.Data)
	if err != nil {
		log.Errorf("Unmarshal failed: %v", err)
		return nil, err
	}
	readTxn := tmp.(*ocs.DataOCS).Read

	// 1) Check signature on the DecReq message
	drd, err := network.Marshal(decReqData)
	if err != nil {
		log.Errorf("Marshal failed: %v", err)
		return nil, err
	}
	tmpHash := sha256.Sum256(drd)
	drdHash := tmpHash[:]
	sigErr := crypto.VerifySchnorr(network.Suite, writeTxn.ReaderPk, drdHash, *sig)

	if sigErr != nil {
		log.Error("Cannot verify DecReq message signature")
		return nil, sigErr
	}

	// 2) Check inclusion proof
	readSBHash := decReqData.ReadTxnSBF.CalculateHash()
	proof := decReqData.InclusionProof

	if len(proof.Signature) == 0 {
		return nil, errors.New("No signature present" + log.Stack())
	}

	hc := proof.Hash.Equal(readSBHash)

	if !hc {
		log.Error("Forward link hash does not match read transaction hash")
		return nil, errors.New("Forward link hash does not match read transaction hash")
	}

	sigErr = cosi.VerifySignature(network.Suite, decReqData.ACPublicKeys, proof.Hash, proof.Signature)

	if sigErr != nil {
		log.Error("Cannot verify forward-link signature")
		return nil, sigErr
	}

	// 3) Check that read contains write's hash
	// Not sure if redundant!
	writeSBHash := decReqData.WriteTxnSBF.CalculateHash()
	hc = readTxn.DataID.Equal(writeSBHash)
	if !hc {
		log.Error("Invalid write block hash in the read block")
		return nil, errors.New("Invalid write block hash in the read block")
	}

	return writeTxn, nil
}
