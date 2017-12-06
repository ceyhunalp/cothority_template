package main

import (
	"bufio"
	"bytes"
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
	// g_s, _ := dataPVSS.Suite.Point().Mul(nil, dataPVSS.Secret).MarshalBinary()
	// symKey := sha256.Sum256(g_s)

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
	// fmt.Println(scurl.Genesis)

	// tmpEncShares, pubPoly, _ := pvss.EncShares(suite, H, pubKeys, s, t)
	// sz := len(tmpEncShares)
	// encShares := make([]pvss.PubVerShare, sz)
	// for i := 0; i < sz; i++ {
	// 	encShares[i] = *tmpEncShares[i]
	// }

	// Creating write transaction
	sbWrite, err := createWriteTransaction(scurl, dataPVSS, pubKey)
	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}
	// fmt.Println("sbWrite hash is", sbWrite.Hash)

	// Get write transaction from skipchain
	writeTxnData, err := getWriteTransaction(scurl, sbWrite.Hash)
	if err != nil {
		log.Errorf("Could not retrieve write transaction: %v", err)
		os.Exit(1)
	}

	// diffSk := dataPVSS.Suite.Scalar().Pick(random.Stream)
	// diffPk := dataPVSS.Suite.Point().Mul(nil, diffSk)
	// sbWriteDiff, _ := createWriteTransaction(scurl, dataPVSS, diffPk)
	// fmt.Println("sbWriteDiff hash is", sbWriteDiff.Hash)

	// TODO: Reader first checks H'=H(c) ?= H_c in the write transaction
	// Creating read transaction
	writeID := sbWrite.Hash
	sbRead, err := createReadTransaction(scurl, writeID, privKey)
	// TESTING!
	// sbRead, err := createReadTransaction(scurl, writeID, diffSk)
	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}
	// fmt.Println("sbRead hash is", sbRead.Hash)
	// fmt.Println("sbRead skipchain id is", sbRead.SkipChainID())

	// sz := len(writeTxnData.PubKeys)
	// for i := 0; i < sz; i++ {
	// 	fmt.Println(writeTxnData.PubKeys[i])
	// }

	// This is carried out by trustees
	// If getReadRequest returns True -- read transaction valid / logged in the skipchain
	// writeID is the hash of the write txn block
	// readID is the hash of the read txn block
	readID := sbRead.Hash
	// diffWriteID := sbWriteDiff.Hash
	hc, err := getReadTransaction(scurl, writeID, readID)
	// hc, err := getReadTransaction(scurl, diffWriteID, readID)

	// hc, err := getReadRequest(scurl, writeID, readID)
	// TODO: Is it necessary to check both?
	if hc != 1 || err != nil {
		log.Errorf("Could not find valid read transaction: %v", err)
		os.Exit(1)
	}
	// fmt.Println("hash check:", hc)

	decShares, err := getDecryptShares(el, writeTxnData.H, writeTxnData.EncShares, writeTxnData.EncProofs)
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

	// TODO: suite, threshold and numTrustee add to write transaction?

	recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, writeTxnData.G, validKeys, validEncShares, validDecShares, dataPVSS.Threshold, dataPVSS.NumTrustee)
	// recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, dataPVSS.G, dataPVSS.PublicKeys, dataPVSS.EncShares, decShares, dataPVSS.Threshold, dataPVSS.NumTrustee)

	if err != nil {
		log.Errorf("Could not recover secret: %v", err)
		os.Exit(1)
	}

	G_s := dataPVSS.Suite.Point().Mul(nil, dataPVSS.Secret)
	fmt.Println("G_s is:\n", G_s)
	fmt.Println("==================")
	fmt.Println("Recovered secret is:\n", recSecret)
}

// func getDecryptShares(el *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) []abstract.Point {
func getDecryptShares(el *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) ([]*pvss.PubVerShare, error) {

	cl := ds.NewClient()
	defer cl.Close()
	decShares, err := cl.Decshare(el, h, encShares, polyCommits)

	if err != nil {
		return decShares, err
	}

	size := len(decShares)
	for i := 0; i < size/2; i++ {
		tmp := decShares[size-i-1]
		decShares[size-i-1] = decShares[i]
		decShares[i] = tmp
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
		fmt.Println("ReadDoc hash is", readDoc.ReadID)
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

func createWriteTransaction(scurl *ocs.SkipChainURL, dp *DataPVSS, pubKey abstract.Point) (sb *skipchain.SkipBlock, err error) {

	cl := ocs.NewClient()
	defer cl.Close()
	readList := make([]abstract.Point, 1)
	readList = append(readList, pubKey)
	sb, err = cl.WriteTransactionRequest(scurl, dp.EncShares, dp.EncProofs, dp.PublicKeys, dp.G, dp.H, readList)
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
