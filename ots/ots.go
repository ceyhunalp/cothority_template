package ots

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"os"

	"github.com/dedis/cothority/skipchain"
	otssc "github.com/dedis/cothority_template/otssc/service"
	ocs "github.com/dedis/onchain-secrets"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestSkipchain(scurl *ocs.SkipChainURL, dp *DataPVSS) {

	mesg := "Bana istediginiz kadar gidip gelebilirsiniz."
	log.Info("Plaintext message is:", mesg)
	encMesg, hashEnc := EncryptMessage(dp, &mesg)
	log.Lvl3(encMesg)
	count := 5
	readerSK := make([]abstract.Scalar, count)
	readerPK := make([]abstract.Point, count)
	sbWrite := make([]*skipchain.SkipBlock, count)
	sbRead := make([]*skipchain.SkipBlock, count)

	for i := 0; i < count; i++ {
		readerSK[i] = dp.Suite.Scalar().Pick(random.Stream)
		readerPK[i] = dp.Suite.Point().Mul(nil, readerSK[i])
		tmp, _ := CreateWriteTransaction(scurl, dp, hashEnc, readerPK[i])
		sbWrite[i] = tmp
	}

	for i := 0; i < count-1; i++ {
		tmp, _ := CreateReadTransaction(scurl, sbWrite[i].Hash, readerSK[i])
		sbRead[i] = tmp
	}

	// for i := 0; i < count; i++ {
	// 	fmt.Println("hash is", sbWrite[i].Data)
	// 	fmt.Println("fwd len is", sbWrite[i].GetForwardLen())
	// 	fmt.Println("bward link is", sbWrite[i].BackLinkIDs[0])
	// 	// fmt.Println("sprint is", sbWrite[i].Sprint(false))
	// 	fmt.Println("index is", sbWrite[i].Index)
	// 	fmt.Println("=====================================")
	// }

}

// func GetDecryptShares(el *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) []abstract.Point {
func GetDecryptShares(scurl *ocs.SkipChainURL, el *onet.Roster, h abstract.Point, scPubKeys []abstract.Point, encShares []*pvss.PubVerShare, encProofs []abstract.Point, writeBlk *skipchain.SkipBlock, index int, readBlkHdr *skipchain.SkipBlockFix, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID) ([]*pvss.PubVerShare, error) {

	cl := otssc.NewClient()
	defer cl.Close()

	idx := index - writeBlk.Index - 1
	if idx < 0 {
		log.Fatal("ForwardLink index is negative")
		os.Exit(1)
	}
	fwdLink := writeBlk.GetForward(idx)

	if fwdLink == nil {
		log.Errorf("Forward does not exist")
		os.Exit(1)
	}

	tmpDecShares, err := cl.OTSDecrypt(el, h, scPubKeys, encShares, encProofs, fwdLink, readBlkHdr, writeHash, readHash)

	if err != nil {
		return tmpDecShares, err
	}

	size := len(tmpDecShares)
	decShares := make([]*pvss.PubVerShare, size)

	for i := 0; i < size; i++ {
		decShares[tmpDecShares[i].S.I] = tmpDecShares[i]
	}

	return decShares, nil
}

func GetUpdatedBlock(scurl *ocs.SkipChainURL, sbid skipchain.SkipBlockID) (*skipchain.SkipBlock, error) {

	cl := skipchain.NewClient()
	defer cl.Close()
	sb, cerr := cl.GetSingleBlock(scurl.Roster, sbid)
	if cerr != nil {
		return nil, cerr
	}
	return sb, nil
}

// Not used anymore
// func GetReadTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, readID skipchain.SkipBlockID) (int, error) {
//
// 	cl := ocs.NewClient()
// 	defer cl.Close()
// 	rd, err := cl.GetReadTransaction(scurl, dataID)
//
// 	if err != nil {
// 		return 0, err
// 	}
//
// 	//TODO: What if returns multiple ReadDoc
// 	//TODO: Returned error values
// 	sz := len(rd)
// 	if sz > 0 {
// 		readDoc := rd[0]
// 		hashCheck := bytes.Compare(readID, readDoc.ReadID)
// 		if hashCheck == 0 {
// 			log.Lvl3("Matching hash values")
// 			return 1, nil
// 		} else {
// 			log.Lvl3("Different hash values")
// 			return 0, err
// 		}
// 	} else {
// 		log.Lvl3("No read transaction found for the given write transaction")
// 		return 0, err
// 	}
// }

func GetWriteTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID) (wtd *WriteTransactionData, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	tmpTxn, err := cl.GetWriteTransaction(scurl, dataID)

	if err != nil {
		return nil, err
	}

	wtd = &WriteTransactionData{
		G:          tmpTxn.G,
		H:          tmpTxn.H,
		PublicKeys: tmpTxn.PublicKeys,
		EncShares:  tmpTxn.EncShares,
		EncProofs:  tmpTxn.EncProofs,
		HashEnc:    tmpTxn.HashEnc,
	}
	return wtd, nil
}

func CreateReadTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, privKey abstract.Scalar) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	sb, cerr := cl.ReadTransactionRequest(scurl, dataID, privKey)
	return sb, cerr
}

func CreateWriteTransaction(scurl *ocs.SkipChainURL, dp *DataPVSS, hashEnc []byte, pubKey abstract.Point) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	readList := make([]abstract.Point, 1)
	readList = append(readList, pubKey)
	sb, err = cl.WriteTxnRequest(scurl, dp.G, dp.H, dp.PublicKeys, dp.EncShares, dp.EncProofs, hashEnc, readList)
	return sb, err
}

func CreateSkipchain(el *onet.Roster) (scurl *ocs.SkipChainURL, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	scurl, err = cl.CreateSkipchain(el)
	return scurl, err
}

func VerifyEncMesg(wtd *WriteTransactionData, encMesg []byte) int {

	tmpHash := sha256.Sum256(encMesg)
	cmptHash := tmpHash[:]
	return bytes.Compare(cmptHash, wtd.HashEnc)
}

func DecryptMessage(recSecret abstract.Point, encMesg []byte, wtd *WriteTransactionData, dp *DataPVSS) (mesg string) {

	g_s, _ := recSecret.MarshalBinary()
	tempSymKey := sha256.Sum256(g_s)
	symKey := tempSymKey[:]
	cipher := network.Suite.Cipher(symKey)
	decMesg, _ := cipher.Open(nil, encMesg)
	mesg = string(decMesg)
	return mesg
}

func EncryptMessage(dp *DataPVSS, msg *string) (encMesg []byte, hashEnc []byte) {

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

func SetupPVSS(pubKeys []abstract.Point, numTrustee int) (dp *DataPVSS, err error) {

	suite := ed25519.NewAES128SHA256Ed25519(false)
	g := suite.Point().Base()
	h, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))
	secret := suite.Scalar().Pick(random.Stream)
	threshold := 2*numTrustee/3 + 1

	// PVSS step
	encShares, commitPoly, err := pvss.EncShares(suite, h, pubKeys, secret, threshold)

	if err == nil {
		encProofs := make([]abstract.Point, numTrustee)
		for i := 0; i < numTrustee; i++ {
			encProofs[i] = commitPoly.Eval(encShares[i].S.I).V
		}
		dp = &DataPVSS{
			NumTrustee: numTrustee,
			Threshold:  threshold,
			Suite:      suite,
			G:          g,
			H:          h,
			Secret:     secret,
			PublicKeys: pubKeys,
			EncShares:  encShares,
			EncProofs:  encProofs,
		}
		return dp, nil
	} else {
		return nil, err
	}
}

// This function can replace the service for polling
// the servers to collect their public keys.
//
func GetPubKeys(fname *string) ([]abstract.Point, error) {

	var keys []abstract.Point
	fh, err := os.Open(*fname)
	defer fh.Close()
	if err != nil {
		return nil, err
	}
	fs := bufio.NewScanner(fh)

	for fs.Scan() {
		tmp, _ := crypto.StringHexToPoint(network.Suite, fs.Text())
		keys = append(keys, tmp)
	}

	return keys, nil
}

// func GetPubKeys(el *onet.Roster) []abstract.Point {
//
// 	cl := keypoll.NewClient()
// 	keys, err := cl.Keypoll(el)
// 	log.ErrFatal(err)
//
// 	size := len(keys)
// 	for i := 0; i < size/2; i++ {
// 		tmp := keys[size-i-1]
// 		keys[size-i-1] = keys[i]
// 		keys[i] = tmp
// 	}
// 	cl.Close()
// 	return keys
// }
