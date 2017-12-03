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
	//tFilePtr := flag.String("t", "", "group.toml file for trustees")
	//cFilePtr := flag.String("c", "", "group.toml file for the cothority")
	flag.Parse()

	log.SetDebugVisible(*dbgPtr)

	el, err := util.ReadRoster(*filePtr)
	log.ErrFatal(err, "Couldn't Read File")
	log.Lvl3(el)

	for i := 0; i < len(el.List); i++ {
		fmt.Println(el.List[i])
	}

	pubKeys := getPubKeys(pkFilePtr)

	// pubKeys := getPubKeys(el)
	// for i := 0; i < len(pubKeys); i++ {
	// 	fmt.Println(pubKeys[i])
	// }

	dataPVSS, _ := setupPVSS(pubKeys)

	// Reader's pk/sk pair
	privKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	pubKey := dataPVSS.Suite.Point().Mul(nil, privKey)

	scurl := createSkipchain(filePtr)
	fmt.Println(scurl.Genesis)

	// tmpEncShares, pubPoly, _ := pvss.EncShares(suite, H, pubKeys, s, t)
	// sz := len(tmpEncShares)
	// encShares := make([]pvss.PubVerShare, sz)
	// for i := 0; i < sz; i++ {
	// 	encShares[i] = *tmpEncShares[i]
	// }

	// Creating write transaction
	sbWrite := createWriteTransaction(scurl, dataPVSS, pubKey)
	fmt.Println("sbWrite hash is", sbWrite.Hash)

	// diffSk := suite.Scalar().Pick(random.Stream)
	// diffPk := suite.Point().Mul(nil, diffSk)
	// sbWriteDiff := createWriteTransaction(scurl, encShares, pubKeys, G, H, diffPk)
	// fmt.Println("sbWriteDiff hash is", sbWriteDiff.Hash)

	// Creating read transaction
	dataID := sbWrite.Hash
	sbRead := createReadTransaction(scurl, dataID, privKey)
	fmt.Println("sbRead hash is", sbRead.Hash)
	fmt.Println("sbRead skipchain id is", sbRead.SkipChainID())

	// Get write transaction from skipchain
	writeTxnData := getWriteTransaction(scurl, sbWrite.Hash)
	sz := len(writeTxnData.PubKeys)
	for i := 0; i < sz; i++ {
		fmt.Println(writeTxnData.PubKeys[i])
	}
	fmt.Println("******************************************************")

	// Get read requests
	// If getReadRequest returns True -- read transaction valid / logged in the skipchain
	readID := sbRead.Hash
	hc := getReadRequest(scurl, dataID, readID)
	fmt.Println("hash check:", hc)

	decShares := getDecryptShares(el, writeTxnData.H, writeTxnData.EncShares, writeTxnData.EncProofs)
	// decShares := getDecryptShares(el, dataPVSS.H, dataPVSS.EncShares, dataPVSS.EncProofs)

	var validKeys []abstract.Point
	var validEncShares []*pvss.PubVerShare
	var validDecShares []*pvss.PubVerShare

	sz = len(decShares)
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

	log.ErrFatal(err)

	G_s := dataPVSS.Suite.Point().Mul(nil, dataPVSS.Secret)
	fmt.Println("G_s is:\n", G_s)
	fmt.Println("==================")
	fmt.Println("Recovered secret is:\n", recSecret)
}

// func getDecryptShares(el *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) []abstract.Point {
func getDecryptShares(el *onet.Roster, h abstract.Point, encShares []*pvss.PubVerShare, polyCommits []abstract.Point) []*pvss.PubVerShare {

	cl := ds.NewClient()
	decShares, err := cl.Decshare(el, h, encShares, polyCommits)
	log.ErrFatal(err)

	size := len(decShares)
	for i := 0; i < size/2; i++ {
		tmp := decShares[size-i-1]
		decShares[size-i-1] = decShares[i]
		decShares[i] = tmp
	}

	return decShares
}

func getReadRequest(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, readID skipchain.SkipBlockID) (hc int) {

	cl := ocs.NewClient()
	rd, err := cl.GetReadRequests(scurl, dataID, 0)
	log.ErrFatal(err)

	//TODO: What if returns multiple ReadDoc
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
			return 1
		} else {
			log.Lvl3("Different hash values")
			return 0
		}
	} else {
		log.Lvl3("No read transaction found for the given write transaction")
		return 0
	}
}

func getWriteTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID) (wtd *WriteTransactionData) {

	cl := ocs.NewClient()
	writeTxn, err := cl.GetWriteTxnData(scurl, dataID)
	txnData := &WriteTransactionData{
		EncShares: writeTxn.EncShares,
		EncProofs: writeTxn.EncProofs,
		G:         writeTxn.G,
		H:         writeTxn.H,
		PubKeys:   writeTxn.PubKeys,
	}
	log.ErrFatal(err)
	return txnData
}

func createReadTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID, privKey abstract.Scalar) (sb *skipchain.SkipBlock) {

	cl := ocs.NewClient()
	sb, cerr := cl.ReadTransactionRequest(scurl, dataID, privKey)
	log.ErrFatal(cerr)
	return sb
}

func createWriteTransaction(scurl *ocs.SkipChainURL, dp *DataPVSS, pubKey abstract.Point) (sb *skipchain.SkipBlock) {

	cl := ocs.NewClient()
	readList := make([]abstract.Point, 1)
	readList = append(readList, pubKey)
	sb, cerr := cl.WriteTransactionRequest(scurl, dp.EncShares, dp.EncProofs, dp.PublicKeys, dp.G, dp.H, readList)
	log.ErrFatal(cerr)
	cl.Close()
	return sb
}

func createSkipchain(groupToml *string) *ocs.SkipChainURL {

	gr := util.GetGroup(*groupToml)
	log.Lvl3(gr)

	cl := ocs.NewClient()
	scurl, err := cl.CreateSkipchain(gr.Roster)
	log.ErrFatal(err)
	//cl.Close()
	return scurl
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

		return dp, err
	}
}

// This function can replace the service for polling
// the servers to collect their public keys.
//
func getPubKeys(fname *string) []abstract.Point {

	var keys []abstract.Point
	fh, _ := os.Open(*fname)
	defer fh.Close()
	fs := bufio.NewScanner(fh)

	for fs.Scan() {
		tmp, _ := crypto.StringHexToPoint(network.Suite, fs.Text())
		keys = append(keys, tmp)
	}

	return keys
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
