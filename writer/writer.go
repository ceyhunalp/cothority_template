package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"github.com/dedis/cothority/skipchain"
	ds "github.com/dedis/cothority_template/decshare/service"
	"github.com/dedis/cothority_template/writer/util"
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

func main() {

	filePtr := flag.String("g", "", "group.toml file for trustees")
	pkFilePtr := flag.String("p", "", "pk.txt file")
	dbgPtr := flag.Int("d", 0, "debug level")
	flag.Parse()

	log.SetDebugVisible(*dbgPtr)

	el, err := util.ReadRoster(*filePtr)

	if err != nil {
		log.Errorf("Couldn't read group.toml file: %v", err)
		os.Exit(1)
	}

	// for i := 0; i < len(el.List); i++ {
	// 	fmt.Println(el.List[i])
	// }

	pubKeys, err := getPubKeys(pkFilePtr)

	if err != nil {
		log.Errorf("Couldn't read pk file: %v", err)
		os.Exit(1)
	}
	// pubKeys := getPubKeys(el)
	// for i := 0; i < len(pubKeys); i++ {
	// 	fmt.Println(pubKeys[i])
	// }

	dataPVSS, err := setupPVSS(pubKeys)

	//TODO: Use symKey to encrypt data
	mesg := "Dunyali dostum, tam olarak anlamadin galiba. KACIRILDIN!"
	log.Info("Plaintext message is:", mesg)
	encMesg, hashEnc := encryptMessage(dataPVSS, &mesg)

	if err != nil {
		log.Errorf("Could not setup PVSS: %v", err)
		os.Exit(1)
	}

	// Reader's pk/sk pair
	privKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	pubKey := dataPVSS.Suite.Point().Mul(nil, privKey)

	scurl, err := createSkipchain(filePtr)
	if err != nil {
		log.Errorf("Could not create skipchain: %v", err)
		os.Exit(1)
	}

	// Creating write transaction
	sbWrite, err := createWriteTransaction(scurl, dataPVSS, hashEnc, pubKey)
	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}

	// fmt.Println("sbWrite hash is", sbWrite.Hash)
	// fmt.Println("sbWrite fwd len is", sbWrite.GetForwardLen())
	// fmt.Println("sbWrite index is", sbWrite.Index)
	// fmt.Println("sbwrite bcklink", sbWrite.BackLinkIDs[0].Short())

	// Get write transaction from skipchain
	writeTxnData, err := getWriteTransaction(scurl, sbWrite.Hash)
	if err != nil {
		log.Errorf("Could not retrieve write transaction: %v", err)
		os.Exit(1)
	}

	validHash := verifyEncMesg(writeTxnData, encMesg)

	if validHash == 0 {
		log.Info("Valid hash for encrypted message")
	} else {
		log.Errorf("Invalid hash for encrypted message")
		os.Exit(1)
	}

	// diffSk := dataPVSS.Suite.Scalar().Pick(random.Stream)
	// diffPk := dataPVSS.Suite.Point().Mul(nil, diffSk)
	// sbWriteDiff, _ := createWriteTransaction(scurl, dataPVSS, diffPk)
	// fmt.Println("sbWriteDiff hash is", sbWriteDiff.Hash)

	// Creating read transaction
	writeID := sbWrite.Hash
	sbRead, err := createReadTransaction(scurl, writeID, privKey)
	// TESTING!
	// sbRead, err := createReadTransaction(scurl, writeID, diffSk)
	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}

	fmt.Println("sbRead hash is", sbRead.Hash)
	fmt.Println("sbRead fwd len is", sbRead.GetForwardLen())
	fmt.Println("sbRead index is", sbRead.Index)
	fmt.Println("sbread bcklink", sbRead.BackLinkIDs[0].Short())

	// This is carried out by trustees
	// If getReadRequest returns True -- read transaction valid / logged in the skipchain
	// writeID is the hash of the write txn block
	// readID is the hash of the read txn block

	readID := sbRead.Hash
	// // diffWriteID := sbWriteDiff.Hash
	// hc, err := getReadTransaction(scurl, writeID, readID)
	// // hc, err := getReadTransaction(scurl, diffWriteID, readID)
	//
	// // hc, err := getReadRequest(scurl, writeID, readID)
	// // TODO: Is it necessary to check both?
	// if hc != 1 || err != nil {
	// 	log.Errorf("Could not find valid read transaction: %v", err)
	// 	os.Exit(1)
	// }

	updWriteBlk, _ := getUpdatedBlock(scurl, writeID)
	fmt.Println("Forward link is:", updWriteBlk.ForwardLink[0].Hash.Short())

	scPubKeys := sbRead.Roster.Publics()

	testSkipchain(scurl, dataPVSS)

	decShares, err := getDecryptShares(el, scurl, updWriteBlk, scPubKeys, updWriteBlk.Hash, readID, sbRead.SkipBlockFix, sbRead.Index, writeTxnData.H, writeTxnData.EncShares, writeTxnData.EncProofs)
	if err != nil {
		log.Errorf("Could not decrypt shares: %v", err)
		os.Exit(1)
	}

	var validKeys []abstract.Point
	var validEncShares []*pvss.PubVerShare
	var validDecShares []*pvss.PubVerShare

	sz := len(decShares)
	for i := 0; i < sz; i++ {
		if decShares != nil {
			validKeys = append(validKeys, writeTxnData.PubKeys[i])
			validEncShares = append(validEncShares, writeTxnData.EncShares[i])
			validDecShares = append(validDecShares, decShares[i])
		}
	}

	recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, writeTxnData.G, validKeys, validEncShares, validDecShares, dataPVSS.Threshold, dataPVSS.NumTrustee)
	// recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, dataPVSS.G, dataPVSS.PublicKeys, dataPVSS.EncShares, decShares, dataPVSS.Threshold, dataPVSS.NumTrustee)

	if err != nil {
		log.Errorf("Could not recover secret: %v", err)
		os.Exit(1)
	}

	recvMesg := decryptMessage(recSecret, encMesg, writeTxnData, dataPVSS)
	log.Info("Recovered message is:", recvMesg)

	// _, msg, _ := network.Unmarshal(sbRead.Data)
	// abbas := msg.(*ocs.DataOCS)
	// fmt.Println(abbas.Read.DataID)
}

func testSkipchain(scurl *ocs.SkipChainURL, dp *DataPVSS) {

	mesg := "Alev seklinde bir top ya da top seklinde bir alev."
	log.Info("Plaintext message is:", mesg)
	encMesg, hashEnc := encryptMessage(dp, &mesg)
	log.Lvl3(encMesg)
	count := 5
	readerSK := make([]abstract.Scalar, count)
	readerPK := make([]abstract.Point, count)
	sbWrite := make([]*skipchain.SkipBlock, count)
	sbRead := make([]*skipchain.SkipBlock, count)

	for i := 0; i < count; i++ {
		readerSK[i] = dp.Suite.Scalar().Pick(random.Stream)
		readerPK[i] = dp.Suite.Point().Mul(nil, readerSK[i])
		tmp, _ := createWriteTransaction(scurl, dp, hashEnc, readerPK[i])
		sbWrite[i] = tmp
	}

	for i := 0; i < count-1; i++ {
		tmp, _ := createReadTransaction(scurl, sbWrite[i].Hash, readerSK[i])
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

func getUpdatedBlock(scurl *ocs.SkipChainURL, sbid skipchain.SkipBlockID) (*skipchain.SkipBlock, error) {

	cl := skipchain.NewClient()
	defer cl.Close()
	sb, cerr := cl.GetSingleBlock(scurl.Roster, sbid)
	if cerr != nil {
		return nil, cerr
	}
	return sb, nil
}

// func getDecryptShares(el *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) []abstract.Point {
func getDecryptShares(el *onet.Roster, scurl *ocs.SkipChainURL, writeBlk *skipchain.SkipBlock, scPubKeys []abstract.Point, writeHash skipchain.SkipBlockID, readHash skipchain.SkipBlockID, readBlkHdr *skipchain.SkipBlockFix, index int, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) ([]*pvss.PubVerShare, error) {

	cl := ds.NewClient()
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

	tmpDecShares, err := cl.Decshare(el, h, encShares, polyCommits, fwdLink, scPubKeys, writeHash, readHash, readBlkHdr)

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

func getReadTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, readID skipchain.SkipBlockID) (int, error) {

	cl := ocs.NewClient()
	defer cl.Close()
	rd, err := cl.GetReadTransaction(scurl, dataID)
	// rd, err := cl.GetReadRequests(scurl, dataID, 0)

	if err != nil {
		return 0, err
	}

	//TODO: What if returns multiple ReadDoc
	//TODO: Returned error values
	sz := len(rd)
	/*
		for i := 0; i < sz; i++ {
			fmt.Println("============ Printing ReadDoc", i, "===============")
			fmt.Println("getReadRequest: ReadDoc.Reader -->", rd[i].Reader)
			// ReadID == Hash of the read block
			fmt.Println("getReadRequest: ReadDoc.ReadID -->", rd[i].ReadID)
			fmt.Println("getReadRequest: ReadDoc.DataID -->", rd[i].DataID)
		}
	*/
	if sz > 0 {
		readDoc := rd[0]
		// fmt.Println("ReadDoc hash is", readDoc.ReadID)
		hashCheck := bytes.Compare(readID, readDoc.ReadID)
		if hashCheck == 0 {
			log.Lvl3("Matching hash values")
			return 1, nil
		} else {
			log.Lvl3("Different hash values")
			return 0, err
		}
	} else {
		log.Lvl3("No read transaction found for the given write transaction")
		return 0, err
	}
}

func getWriteTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID) (wtd *WriteTransactionData, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	tmpTxn, err := cl.GetWriteTransaction(scurl, dataID)

	if err != nil {
		// log.Errorf("Couldn't get write transaction: %v", err)
		return nil, err
	}

	wtd = &WriteTransactionData{
		EncShares: tmpTxn.EncShares,
		EncProofs: tmpTxn.EncProofs,
		G:         tmpTxn.G,
		H:         tmpTxn.H,
		HashEnc:   tmpTxn.HashEnc,
		PubKeys:   tmpTxn.PubKeys,
	}
	return wtd, nil
}

func createReadTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, privKey abstract.Scalar) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	sb, cerr := cl.ReadTransactionRequest(scurl, dataID, privKey)
	return sb, cerr
}

func createWriteTransaction(scurl *ocs.SkipChainURL, dp *DataPVSS, hashEnc []byte, pubKey abstract.Point) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	readList := make([]abstract.Point, 1)
	readList = append(readList, pubKey)
	sb, err = cl.WriteTransactionRequest(scurl, dp.EncShares, dp.EncProofs, dp.PublicKeys, dp.G, dp.H, hashEnc, readList)
	// if err != nil {
	// 	log.Errorf("Couldn't create write transaction: %v", err)
	// }
	return sb, err
}

func createSkipchain(groupToml *string) (scurl *ocs.SkipChainURL, err error) {

	gr := util.GetGroup(*groupToml)
	log.Lvl3(gr)

	cl := ocs.NewClient()
	defer cl.Close()
	scurl, err = cl.CreateSkipchain(gr.Roster)
	return scurl, err
}

func verifyEncMesg(wtd *WriteTransactionData, encMesg []byte) int {

	tmpHash := sha256.Sum256(encMesg)
	cmptHash := tmpHash[:]
	return bytes.Compare(cmptHash, wtd.HashEnc)
}

func decryptMessage(recSecret abstract.Point, encMesg []byte, wtd *WriteTransactionData, dp *DataPVSS) (mesg string) {

	g_s, _ := recSecret.MarshalBinary()
	tempSymKey := sha256.Sum256(g_s)
	symKey := tempSymKey[:]
	cipher := network.Suite.Cipher(symKey)
	decMesg, _ := cipher.Open(nil, encMesg)
	mesg = string(decMesg)
	return mesg
}

func encryptMessage(dp *DataPVSS, msg *string) (encMesg []byte, hashEnc []byte) {

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

func setupPVSS(pubKeys []abstract.Point) (dp *DataPVSS, err error) {

	suite := ed25519.NewAES128SHA256Ed25519(false)
	g := suite.Point().Base()
	h, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))
	secret := suite.Scalar().Pick(random.Stream)
	numTrustee := 7
	threshold := 2*numTrustee/3 + 1

	// PVSS step
	encShares, commitPoly, err := pvss.EncShares(suite, h, pubKeys, secret, threshold)

	if err != nil {
		// log.Errorf("Could not create DataPVSS: %v", err)
		return nil, err
	} else {
		dp = &DataPVSS{
			Suite:      suite,
			G:          g,
			H:          h,
			NumTrustee: numTrustee,
			Threshold:  threshold,
			Secret:     secret,
			PublicKeys: pubKeys,
			EncShares:  encShares,
			EncProofs:  make([]abstract.Point, numTrustee),
		}

		for i := 0; i < numTrustee; i++ {
			dp.EncProofs[i] = commitPoly.Eval(dp.EncShares[i].S.I).V
		}

		return dp, nil
	}
}

// This function can replace the service for polling
// the servers to collect their public keys.
//
func getPubKeys(fname *string) ([]abstract.Point, error) {

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

// func getPubKeys(el *onet.Roster) []abstract.Point {
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
