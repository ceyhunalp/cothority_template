package service

import (
	"math/rand"

	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/cothority_template/ots/util"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(ServiceName)}
}

func (c *Client) OTSDecrypt(r *onet.Roster, writeTxnSBF *skipchain.SkipBlockFix, readTxnSBF *skipchain.SkipBlockFix, merkleProof *skipchain.BlockLink, acPubKeys []abstract.Point, privKey abstract.Scalar) ([]*util.ReencryptedShare, onet.ClientError) {

	// network.RegisterMessage(&util.OTSDecryptReqData{})
	data := &util.OTSDecryptReqData{
		WriteTxnSBF:  writeTxnSBF,
		ReadTxnSBF:   readTxnSBF,
		MerkleProof:  merkleProof,
		ACPublicKeys: acPubKeys,
	}

	msg, err := network.Marshal(data)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParse, err.Error())
	}

	sig, err := util.SignMessage(msg, privKey)
	// tmpHash := sha256.Sum256(temp)
	// mesgHash := tmpHash[:]
	// sig, err := crypto.SignSchnorr(network.Suite, privKey, mesgHash)

	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParse, err.Error())
	}

	decryptReq := &OTSDecryptReq{
		Roster:    r,
		Data:      data,
		Signature: &sig,
	}

	log.Lvl3("Roster length is", len(r.List))

	idx := rand.Int() % len(r.List)
	dst := r.List[idx]
	decryptReq.RootIndex = idx

	log.Info("Root is", dst.String(), "-- Index:", idx)

	reply := &OTSDecryptResp{}
	err = c.SendProtobuf(dst, decryptReq, reply)
	if err != nil {
		return nil, onet.NewClientErrorCode(ErrorParse, err.Error())
	}

	if idx != 0 {
		for i := 0; i < len(r.List); i++ {
			tmp := reply.DecShares[i]
			if tmp.Index == 0 {
				reply.DecShares[i].Index = idx
			} else if tmp.Index <= idx {
				reply.DecShares[i].Index--
			}
		}
	}

	return reply.DecShares, nil
}

// func (c *Client) OTSDecrypt(r *onet.Roster, h abstract.Point, acPubKeys []abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point, fwdLink *skipchain.BlockLink, readBlkHdr *skipchain.SkipBlockFix, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID, privKey abstract.Scalar) ([]*util.ReencryptedShare, onet.ClientError) {
// 	// func (c *Client) OTSDecrypt(r *onet.Roster, h abstract.Point, acPubKeys []abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point, fwdLink *skipchain.BlockLink, readBlkHdr *skipchain.SkipBlockFix, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID, sig *crypto.SchnorrSig) ([]*pvss.PubVerShare, onet.ClientError) {
//
// 	sig, cerr := crypto.SignSchnorr(network.Suite, privKey, []byte(readHash))
// 	if cerr != nil {
// 		return nil, onet.NewClientErrorCode(ErrorParse, cerr.Error())
// 	}
//
// 	decryptReq := &OTSDecryptReq{
// 		Roster:       r,
// 		H:            h,
// 		ACPublicKeys: acPubKeys,
// 		// EncShares:    encShares,
// 		// EncProofs:    encProofs,
// 		FwdLink:    fwdLink,
// 		ReadBlkHdr: readBlkHdr,
// 		WriteHash:  writeHash,
// 		ReadHash:   readHash,
// 		Signature:  &sig,
// 	}
//
// 	if len(r.List) == 0 {
// 		log.Lvl3("Roster list is empty")
// 	}
//
// 	log.Lvl3("Roster length is", len(r.List))
//
// 	//Random send
// 	// idx := 4
// 	idx := rand.Int() % len(r.List)
// 	// dst := r.RandomServerIdentity()
// 	dst := r.List[idx]
// 	// decryptReq.RootIndex = idx
//
// 	if idx != 0 {
// 		tmpSh := encShares[idx]
// 		tmpPf := encProofs[idx]
// 		for i := idx; i > 0; i-- {
// 			encShares[i] = encShares[i-1]
// 			encProofs[i] = encProofs[i-1]
// 		}
//
// 		encShares[0] = tmpSh
// 		encProofs[0] = tmpPf
// 	}
//
// 	decryptReq.EncShares = encShares
// 	decryptReq.EncProofs = encProofs
//
// 	for i := 0; i < len(encShares); i++ {
// 		fmt.Println("In API:", decryptReq.EncShares[i].S.I)
// 	}
//
// 	log.Info("Root Index is", idx, dst.String())
// 	log.Lvl3("Sending message to", dst)
// 	reply := &OTSDecryptResp{}
// 	err := c.SendProtobuf(dst, decryptReq, reply)
// 	if err != nil {
// 		return nil, err
// 	}
// 	log.Lvl3("Returning from OTSDecrpyt")
// 	log.Info("reply.decshares size is", len(reply.DecShares))
//
// 	if idx != 0 {
// 		for i := 0; i < len(r.List); i++ {
// 			tmp := reply.DecShares[i]
// 			if tmp.Index == 0 {
// 				reply.DecShares[i].Index = idx
// 			} else if tmp.Index <= idx {
// 				reply.DecShares[i].Index--
// 			}
// 		}
// 	}
//
// 	return reply.DecShares, nil
// }
