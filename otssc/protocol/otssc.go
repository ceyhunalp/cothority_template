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
	network.RegisterMessage(&util.ReencryptedShare{})
	network.RegisterMessage(&pvss.PubVerShare{})
	onet.GlobalProtocolRegister(Name, NewProtocol)
}

type OTSDecrypt struct {
	*onet.TreeNodeInstance
	ChannelAnnounce chan StructAnnounceDecrypt
	ChannelReply    chan []StructDecryptReply
	DecShares       chan []*util.ReencryptedShare
	DecReqData      *util.OTSDecryptReqData
	Signature       *crypto.SchnorrSig
	RootIndex       int
}

// type OTSDecrypt struct {
// 	*onet.TreeNodeInstance
// 	ChannelAnnounce chan StructAnnounceDecrypt
// 	ChannelReply    chan []StructDecryptReply
// 	DecShares       chan []*util.ReencryptedShare
// 	// DecShares       chan []ReencReply
// 	// DecShares       chan []*ReencReply
// 	// DecShares       chan []*pvss.PubVerShare
// 	// RootIndex    int
// 	H            abstract.Point
// 	ACPublicKeys []abstract.Point
// 	EncShares    []*pvss.PubVerShare
// 	EncProofs    []abstract.Point
// 	FwdLink      *skipchain.BlockLink
// 	ReadBlkHdr   *skipchain.SkipBlockFix
// 	WriteHash    skipchain.SkipBlockID
// 	ReadHash     skipchain.SkipBlockID
// 	Signature    *crypto.SchnorrSig
// }

func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	otsDecrypt := &OTSDecrypt{
		TreeNodeInstance: n,
		DecShares:        make(chan []*util.ReencryptedShare),
		// DecShares:        make(chan []ReencReply),
		// DecShares:        make(chan []*ReencReply),
		// DecShares:        make(chan []*pvss.PubVerShare),
	}
	err := otsDecrypt.RegisterChannel(&otsDecrypt.ChannelAnnounce)
	if err != nil {
		return nil, errors.New("couldn't register announcement-channel: " + err.Error())
	}
	err = otsDecrypt.RegisterChannel(&otsDecrypt.ChannelReply)
	if err != nil {
		return nil, errors.New("couldn't register reply-channel: " + err.Error())
	}
	return otsDecrypt, nil
}

func (p *OTSDecrypt) Start() error {
	log.Lvl3("Starting OTSDecrypt")
	// log.Info("I am --> ", p.Index(), p.Name(), p.Roster().Get(p.Index()).String())
	for _, c := range p.Children() {
		// idx := c.RosterIndex

		log.Info("In OTSSC:", *p.Signature)
		err := p.SendTo(c, &AnnounceDecrypt{
			DecReqData: p.DecReqData,
			Signature:  p.Signature,
			RootIndex:  p.RootIndex,
		})

		// err := p.SendTo(c, &AnnounceDecrypt{
		// 	H:            p.H,
		// 	ACPublicKeys: p.ACPublicKeys,
		// 	EncShare:     p.EncShares[idx],
		// 	EncProof:     p.EncProofs[idx],
		// 	FwdLink:      p.FwdLink,
		// 	ReadBlkHdr:   p.ReadBlkHdr,
		// 	WriteHash:    p.WriteHash,
		// 	ReadHash:     p.ReadHash,
		// 	Signature:    p.Signature,
		// })

		if err != nil {
			log.Error(p.Info(), "failed to send to", c.Name(), err)
		}
	}
	return nil
}

func (p *OTSDecrypt) Dispatch() error {
	if p.IsLeaf() {
		// log.Info("I am --> ", p.Index(), p.Name(), p.Roster().Get(p.Index()).String())

		announcement := <-p.ChannelAnnounce
		writeTxnData, sigErr := verifyDecryptionRequest(announcement.DecReqData, announcement.Signature)
		// pubKey, validSignErr := verifyDecryptionRequest(announcement.FwdLink, announcement.ACPublicKeys, announcement.WriteHash, announcement.ReadHash, announcement.ReadBlkHdr, announcement.Signature)
		if sigErr != nil {
			// log.Error(p.Info(), "Failed to verify decryption request", sigErr)
			return sigErr
		}
		idx := p.Index()
		if idx <= announcement.RootIndex {
			idx--
		}

		ds, err := pvss.DecShare(network.Suite, writeTxnData.H, p.Public(), writeTxnData.EncProofs[idx], p.Private(), writeTxnData.EncShares[idx])

		if err != nil {
			log.Error(p.Info(), "Failed to decrypt share", p.Parent().Name(), err)
			return err
		}

		ctext := reencryptShare(ds, writeTxnData.ReaderPk, p.Private())
		// ctext := reencryptShare(ds, pubKey, p.Private())
		reencSh := &util.ReencryptedShare{
			Index: p.Index(),
			Data:  ctext,
		}
		// if err != nil {
		// 	log.Error(p.Info(), "Failed to reencrypt share", p.Parent().Name(), err)
		// 	return err
		// }

		err = p.SendTo(p.Parent(), &DecryptReply{reencSh})
		// err = p.SendTo(p.Parent(), &DecryptReply{ds})

		if err != nil {
			log.Error(p.Info(), "Failed to send reply to", p.Parent().Name(), err)
			return err
		}

		return nil
	}

	var reencShares []*util.ReencryptedShare
	// var reencShares []ReencReply
	// var decShares []*pvss.PubVerShare
	// idx := p.Index()
	// idx := p.RootIndex
	idx := p.RootIndex
	reply := <-p.ChannelReply

	for _, c := range reply {
		reencShares = append(reencShares, c.DecryptReply.DecShare)
		// decShares = append(decShares, c.DecryptReply.DecShare)
	}

	writeTxnData, sigErr := verifyDecryptionRequest(p.DecReqData, p.Signature)
	// pubKey, validSignErr := verifyDecryptionRequest(p.FwdLink, p.ACPublicKeys, p.WriteHash, p.ReadHash, p.ReadBlkHdr, p.Signature)
	if sigErr != nil {
		// log.Error(p.Info(), "Failed to verify forward link", validSignErr)
		return sigErr
	}

	ds, err := pvss.DecShare(network.Suite, writeTxnData.H, p.Public(), writeTxnData.EncProofs[idx], p.Private(), writeTxnData.EncShares[idx])

	if err != nil {
		log.Error(p.Info(), "Failed to decrypt share", p.Parent().Name(), err)
		return err
	}

	ctext := reencryptShare(ds, writeTxnData.ReaderPk, p.Private())
	reencSh := &util.ReencryptedShare{
		Index: p.Index(),
		Data:  ctext,
	}
	// if err != nil {
	// 	log.Error(p.Info(), "Failed to reencrypt share", p.Parent().Name(), err)
	// 	return err
	// }

	reencShares = append(reencShares, reencSh)
	// decShares = append(decShares, ds)

	log.Lvl3(p.ServerIdentity().Address, "is done with total of", len(reencShares))
	p.DecShares <- reencShares
	// p.DecShares <- decShares
	return nil
}

func reencryptShare(ds *pvss.PubVerShare, rPubKey abstract.Point, privKey abstract.Scalar) []byte {
	// func reencryptShare(ds *pvss.PubVerShare, rPubKey abstract.Point, privKey abstract.Scalar) *util.ReencryptedShare {
	// func reencryptShare(pubKey abstract.Point, ds *pvss.PubVerShare) ReencReply {
	// func reencryptShare(pubKey abstract.Point, ds *pvss.PubVerShare) (K, C abstract.Point, remainder []byte) {

	mesg, err := network.Marshal(ds)
	// log.Info("In reencrypt share:", ds.S.I)
	if err != nil {
		log.Error("Failed to marshall", err)
		return nil
	}

	shSec, err := network.Suite.Point().Mul(rPubKey, privKey).MarshalBinary()
	log.Info("Shared secret in proto:", shSec)
	if err != nil {
		log.Errorf("MarshalBinary failed: %v", err)
		return nil
	}
	tempSymKey := sha256.Sum256(shSec)
	symKey := tempSymKey[:]
	cipher := network.Suite.Cipher(symKey)
	reencShare := cipher.Seal(nil, mesg)
	return reencShare
	// // Embed the message (or as much of it as will fit) into a curve point.
	// M, _ := network.Suite.Point().Pick(mesg, random.Stream)
	// // ElGamal-encrypt the point to produce ciphertext (K,C).
	// k := network.Suite.Scalar().Pick(random.Stream) // ephemeral private key
	// K := network.Suite.Point().Mul(nil, k)          // ephemeral DH public key
	// S := network.Suite.Point().Mul(pubKey, k)       // ephemeral DH shared secret
	// C := S.Add(S, M)                                // message blinded with secret

	// log.Info("In otssc.go -- share:", K.String())
	//
	// tmp := &util.ReencryptedShare{
	// 	K: K,
	// 	C: C,
	// }

	// tmp := ReencReply{
	// 	K: K,
	// 	C: C,
	// }

	// return tmp
}

// func reencryptShare(ds *pvss.PubVerShare, pubKey abstract.Point) ([]byte, error) {
//
// 	key, err := pubKey.MarshalBinary()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	msg, err := network.Marshal(ds)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	cipher := network.Suite.Cipher(key)
// 	encMesg := cipher.Seal(nil, msg)
// 	return encMesg, nil
// }

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

	// log.Info("Write txn:", writeTxn.HashEnc)
	// log.Info("Read txn:", readTxn.DataID)

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

	// 2) Check Merkle proof

	readSBHash := decReqData.ReadTxnSBF.CalculateHash()
	proof := decReqData.MerkleProof

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

// func verifyDecryptionRequest(bl *skipchain.BlockLink, publics []abstract.Point, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID, readBlkHdr *skipchain.SkipBlockFix, sig *crypto.SchnorrSig) (abstract.Point, error) {
//
// 	if len(bl.Signature) == 0 {
// 		return nil, errors.New("No signature present" + log.Stack())
// 	}
//
// 	hc := bl.Hash.Equal(readHash)
//
// 	if !hc {
// 		log.Lvl3("Forward link hash does not match read transaction hash")
// 		return nil, errors.New("Forward link hash does not match read transaction hash")
// 	}
//
// 	log.Lvl3("Forward link hash matches read transaction hash")
//
// 	signErr := cosi.VerifySignature(network.Suite, publics, bl.Hash, bl.Signature)
//
// 	if signErr != nil {
// 		return nil, signErr
// 	}
//
// 	readBlkHash := readBlkHdr.CalculateHash()
// 	_, tmp, _ := network.Unmarshal(readBlkHdr.Data)
// 	readBlk := tmp.(*ocs.DataOCS).Read
//
// 	hc = readBlkHash.Equal(readHash)
//
// 	if !hc {
// 		log.Lvl3("Hash in read block header not valid")
// 		return nil, errors.New("Hash in read block header not valid")
// 	}
//
// 	log.Lvl3("Valid hash in read block header")
//
// 	hc = readBlk.DataID.Equal(writeHash)
// 	if !hc {
// 		log.Lvl3("Invalid write block hash in the read block")
// 		return nil, errors.New("Invalid write block hash in the read block")
// 	}
//
// 	pubKey := readBlk.Public
// 	err := crypto.VerifySchnorr(network.Suite, pubKey, readHash, *sig)
//
// 	if err != nil {
// 		return nil, errors.New("Signature on the decryption request does not match the public key in the read transaction")
// 	}
//
// 	return pubKey, nil
// }
