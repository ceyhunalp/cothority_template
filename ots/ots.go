package ots

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"os"

	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/cothority_template/ots/util"
	otssc "github.com/dedis/cothority_template/otssc/service"
	ocs "github.com/dedis/onchain-secrets"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func AddDummyTxnPairs(scurl *ocs.SkipChainURL, dp *util.DataPVSS, pairCount int) error {
	mesg := "Bana istediginiz kadar gidip gelebilirsiniz."
	encMesg, hashEnc := EncryptMessage(dp, &mesg)
	log.Lvl3(encMesg)

	writerSK := make([]abstract.Scalar, pairCount)
	writerPK := make([]abstract.Point, pairCount)
	readerSK := make([]abstract.Scalar, pairCount)
	readerPK := make([]abstract.Point, pairCount)
	sbWrite := make([]*skipchain.SkipBlock, pairCount)
	sbRead := make([]*skipchain.SkipBlock, pairCount)

	for i := 0; i < pairCount; i++ {
		readerSK[i] = dp.Suite.Scalar().Pick(random.Stream)
		readerPK[i] = dp.Suite.Point().Mul(nil, readerSK[i])
		writerSK[i] = dp.Suite.Scalar().Pick(random.Stream)
		writerPK[i] = dp.Suite.Point().Mul(nil, writerSK[i])
		tmp, err := CreateWriteTxn(scurl, dp, hashEnc, readerPK[i], writerSK[i])
		if err != nil {
			return err
		}
		sbWrite[i] = tmp
	}

	for i := 0; i < pairCount-1; i++ {
		tmp, err := CreateReadTxn(scurl, sbWrite[i].Hash, readerSK[i])
		if err != nil {
			return err
		}
		sbRead[i] = tmp
	}
	return nil
}

// func TestSkipchain(scurl *ocs.SkipChainURL, dp *util.DataPVSS) {
//
// 	mesg := "Bana istediginiz kadar gidip gelebilirsiniz."
// 	encMesg, hashEnc := EncryptMessage(dp, &mesg)
// 	log.Lvl3(encMesg)
// 	count := 5
// 	writerSK := make([]abstract.Scalar, count)
// 	writerPK := make([]abstract.Point, count)
// 	readerSK := make([]abstract.Scalar, count)
// 	readerPK := make([]abstract.Point, count)
// 	sbWrite := make([]*skipchain.SkipBlock, count)
// 	sbRead := make([]*skipchain.SkipBlock, count)
//
// 	for i := 0; i < count; i++ {
// 		readerSK[i] = dp.Suite.Scalar().Pick(random.Stream)
// 		readerPK[i] = dp.Suite.Point().Mul(nil, readerSK[i])
// 		writerSK[i] = dp.Suite.Scalar().Pick(random.Stream)
// 		writerPK[i] = dp.Suite.Point().Mul(nil, writerSK[i])
// 		tmp, _ := CreateWriteTxn(scurl, dp, hashEnc, readerPK[i], writerSK[i])
// 		sbWrite[i] = tmp
// 	}
//
// 	for i := 0; i < count-1; i++ {
// 		tmp, _ := CreateReadTxn(scurl, sbWrite[i].Hash, readerSK[i])
// 		sbRead[i] = tmp
// 	}
//
// }

func DHDecrypt(shares []*util.DecryptedShare, scPubKeys []abstract.Point, privKey abstract.Scalar) ([]*pvss.PubVerShare, error) {

	// network.RegisterMessage(&pvss.PubVerShare{})
	size := len(shares)
	decShares := make([]*pvss.PubVerShare, size)

	for i := 0; i < size; i++ {
		tmp := shares[i]
		shSec, err := network.Suite.Point().Mul(scPubKeys[tmp.Index], privKey).MarshalBinary()
		if err != nil {
			return nil, err
		}
		tempSymKey := sha256.Sum256(shSec)
		symKey := tempSymKey[:]
		cipher := network.Suite.Cipher(symKey)
		decMesg, err := cipher.Open(nil, tmp.Data)
		if err != nil {
			return nil, err
		}
		_, tmpSh, err := network.Unmarshal(decMesg)
		if err != nil {
			return nil, err
		}
		sh := tmpSh.(*pvss.PubVerShare)
		decShares[i] = sh
	}
	return decShares, nil
}

func GetDecryptedShares(scurl *ocs.SkipChainURL, el *onet.Roster, writeTxnSB *skipchain.SkipBlock, readTxnSBF *skipchain.SkipBlockFix, acPubKeys []abstract.Point, scPubKeys []abstract.Point, privKey abstract.Scalar, index int) ([]*pvss.PubVerShare, error) {

	cl := otssc.NewClient()
	defer cl.Close()

	idx := index - writeTxnSB.Index - 1
	if idx < 0 {
		return nil, errors.New("Forward-link index is negative")
	}
	inclusionProof := writeTxnSB.GetForward(idx)

	if inclusionProof == nil {
		return nil, errors.New("Forward-link does not exist")
	}

	reencShares, cerr := cl.OTSDecrypt(el, writeTxnSB.SkipBlockFix, readTxnSBF, inclusionProof, acPubKeys, privKey)

	if cerr != nil {
		return nil, cerr
	}

	tmpDecShares, err := DHDecrypt(reencShares, scPubKeys, privKey)

	if err != nil {
		return nil, err
	}

	size := len(tmpDecShares)
	decShares := make([]*pvss.PubVerShare, size)

	for i := 0; i < size; i++ {
		decShares[tmpDecShares[i].S.I] = tmpDecShares[i]
	}

	return decShares, nil
}

func GetUpdatedWriteTxnSB(scurl *ocs.SkipChainURL, sbid skipchain.SkipBlockID) (*skipchain.SkipBlock, error) {

	cl := skipchain.NewClient()
	defer cl.Close()
	sb, cerr := cl.GetSingleBlock(scurl.Roster, sbid)
	if cerr != nil {
		return nil, cerr
	}
	return sb, nil
}

func CreateReadTxn(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, privKey abstract.Scalar) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	sb, cerr := cl.ReadTxnRequest(scurl, dataID, privKey)
	return sb, cerr
}

func VerifyTxnSignature(writeTxnData *util.WriteTxnData, sig *crypto.SchnorrSig, wrPubKey abstract.Point) error {

	// network.RegisterMessage(&util.WriteTxnData{})
	wtd, err := network.Marshal(writeTxnData)
	if err != nil {
		return err
	}
	tmpHash := sha256.Sum256(wtd)
	wtdHash := tmpHash[:]
	return crypto.VerifySchnorr(network.Suite, wrPubKey, wtdHash, *sig)
}

func GetWriteTxnSB(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID) (sbWrite *skipchain.SkipBlock, writeTxnData *util.WriteTxnData, sig *crypto.SchnorrSig, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	sbWrite, tmpTxn, err := cl.GetWriteTxn(scurl, dataID)
	if err != nil {
		return nil, nil, nil, err
	}

	sig = tmpTxn.Signature
	writeTxnData = &util.WriteTxnData{
		G: tmpTxn.Data.G,
		// H:            tmpTxn.Data.H,
		SCPublicKeys: tmpTxn.Data.SCPublicKeys,
		EncShares:    tmpTxn.Data.EncShares,
		EncProofs:    tmpTxn.Data.EncProofs,
		HashEnc:      tmpTxn.Data.HashEnc,
		ReaderPk:     tmpTxn.Data.ReaderPk,
	}
	return sbWrite, writeTxnData, sig, nil
}

func CreateWriteTxn(scurl *ocs.SkipChainURL, dp *util.DataPVSS, hashEnc []byte, pubKey abstract.Point, wrPrivKey abstract.Scalar) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	readList := make([]abstract.Point, 1)
	readList[0] = pubKey
	sb, err = cl.WriteTxnRequest(scurl, dp.G, dp.SCPublicKeys, dp.EncShares, dp.EncProofs, hashEnc, readList, wrPrivKey)
	// sb, err = cl.WriteTxnRequest(scurl, dp.G, dp.H, dp.SCPublicKeys, dp.EncShares, dp.EncProofs, hashEnc, readList, wrPrivKey)
	return sb, err
}

func CreateSkipchain(el *onet.Roster) (scurl *ocs.SkipChainURL, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	scurl, err = cl.CreateSkipchain(el)
	return scurl, err
}

func VerifyEncMesg(wtd *util.WriteTxnData, encMesg []byte) int {

	tmpHash := sha256.Sum256(encMesg)
	cmptHash := tmpHash[:]
	return bytes.Compare(cmptHash, wtd.HashEnc)
}

func DecryptMessage(recSecret abstract.Point, encMesg []byte, wtd *util.WriteTxnData) (mesg string) {

	g_s, _ := recSecret.MarshalBinary()
	tempSymKey := sha256.Sum256(g_s)
	symKey := tempSymKey[:]
	cipher := network.Suite.Cipher(symKey)
	decMesg, _ := cipher.Open(nil, encMesg)
	mesg = string(decMesg)
	return mesg
}

func EncryptMessage(dp *util.DataPVSS, msg *string) (encMesg []byte, hashEnc []byte) {

	mesg := []byte(*msg)
	g_s, _ := dp.Suite.Point().Mul(nil, dp.Secret).MarshalBinary()
	tempSymKey := sha256.Sum256(g_s)
	symKey := tempSymKey[:]
	cipher := network.Suite.Cipher(symKey)
	encMesg = cipher.Seal(nil, mesg)
	tempHash := sha256.Sum256(encMesg)
	hashEnc = tempHash[:]
	return encMesg, hashEnc
}

func SetupPVSS(dp *util.DataPVSS, pubKey abstract.Point) error {
	// func SetupPVSS(scPubKeys []abstract.Point, numTrustee int) (dp *util.DataPVSS, err error) {

	// suite := ed25519.NewAES128SHA256Ed25519(false)
	g := dp.Suite.Point().Base()
	// binPubKey, err := pubKey.MarshalBinary()
	// if err != nil {
	// 	return err
	// }
	// tmpHash := sha256.Sum256(binPubKey)
	// labelHash := tmpHash[:]
	// h, _ := dp.Suite.Point().Pick(nil, dp.Suite.Cipher(labelHash))
	h, err := util.CreatePointH(dp.Suite, pubKey)
	if err != nil {
		return err
	}

	// h, _ := dp.Suite.Point().Pick(nil, dp.Suite.Cipher([]byte("H")))
	secret := dp.Suite.Scalar().Pick(random.Stream)
	threshold := 2*dp.NumTrustee/3 + 1

	// PVSS step
	encShares, commitPoly, err := pvss.EncShares(dp.Suite, h, dp.SCPublicKeys, secret, threshold)

	if err == nil {
		encProofs := make([]abstract.Point, dp.NumTrustee)
		for i := 0; i < dp.NumTrustee; i++ {
			encProofs[i] = commitPoly.Eval(encShares[i].S.I).V
		}

		dp.Threshold = threshold
		dp.G = g
		dp.H = h
		dp.Secret = secret
		dp.EncShares = encShares
		dp.EncProofs = encProofs
		return nil
		// dp = &util.DataPVSS{
		// 	NumTrustee:   numTrustee,
		// 	Threshold:    threshold,
		// 	Suite:        suite,
		// 	G:            g,
		// 	H:            h,
		// 	Secret:       secret,
		// 	SCPublicKeys: scPubKeys,
		// 	EncShares:    encShares,
		// 	EncProofs:    encProofs,
		// }
		// return dp, nil
	} else {
		return err
		// return nil, err
	}
}

func GetPubKeys(fname *string) ([]abstract.Point, error) {

	var keys []abstract.Point
	fh, err := os.Open(*fname)
	defer fh.Close()
	if err != nil {
		return nil, err
	}
	fs := bufio.NewScanner(fh)

	for fs.Scan() {
		// tmp, _ := crypto.StringHexToPoint(network.Suite, fs.Text())
		tmp, _ := crypto.String64ToPoint(network.Suite, fs.Text())
		keys = append(keys, tmp)
	}

	return keys, nil
}
