package main

import (
	"bytes"
	"flag"
	"fmt"

	"github.com/dedis/cothority/skipchain"
	ds "github.com/dedis/cothority_template/decshare/service"
	keypoll "github.com/dedis/cothority_template/keypoll/service"
	"github.com/dedis/cothority_template/writer/util"
	ocs "github.com/dedis/onchain-secrets"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

type WriteTransactionData struct {
	EncShares []pvss.PubVerShare
	PubKeys   []abstract.Point
	G         abstract.Point
	H         abstract.Point
}

func main() {

	filePtr := flag.String("g", "", "group.toml file for trustees")
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

	pubKeys := getPubKeys(el)

	for i := 0; i < len(pubKeys); i++ {
		fmt.Println(pubKeys[i])
	}

	scurl := createSkipchain(filePtr)
	fmt.Println(scurl.Genesis)

	suite := ed25519.NewAES128SHA256Ed25519(false)
	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	// Reader's pk/sk pair
	privKey := suite.Scalar().Pick(random.Stream)
	pubKey := suite.Point().Mul(nil, privKey)

	// PVSS step
	s := suite.Scalar().Pick(random.Stream)
	n := 7
	t := 2*n/3 + 1
	tmpEncShares, pubPoly, _ := pvss.EncShares(suite, H, pubKeys, s, t)
	sz := len(tmpEncShares)
	encShares := make([]pvss.PubVerShare, sz)

	for i := 0; i < sz; i++ {
		encShares[i] = *tmpEncShares[i]
	}

	polyCommits := make([]abstract.Point, n)

	for i := 0; i < n; i++ {
		polyCommits[i] = pubPoly.Eval(tmpEncShares[i].S.I).V
	}

	// Creating write transaction
	sbWrite := createWriteTransaction(scurl, encShares, pubKeys, G, H, pubKey)
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
	sz = len(writeTxnData.PubKeys)
	for i := 0; i < sz; i++ {
		fmt.Println(writeTxnData.PubKeys[i])
	}
	fmt.Println("******************************************************")

	// Get read requests
	// If getReadRequest returns True -- read transaction valid / logged in the skipchain
	readID := sbRead.Hash
	hc := getReadRequest(scurl, dataID, readID)
	fmt.Println("hash check:", hc)

	decShares := getDecryptShares(el, H, tmpEncShares, polyCommits)

	fmt.Println(len(decShares))
	for i := 0; i < len(decShares); i++ {
		fmt.Println(decShares[i].S.V)
	}

	recSecret, err := pvss.RecoverSecret(suite, G, pubKeys, tmpEncShares, decShares, t, n)

	log.ErrFatal(err)

	G_s := suite.Point().Mul(nil, s)
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

func createWriteTransaction(scurl *ocs.SkipChainURL, encShares []pvss.PubVerShare, pubKeys []abstract.Point, G abstract.Point, H abstract.Point, pubKey abstract.Point) (sb *skipchain.SkipBlock) {

	cl := ocs.NewClient()
	readList := make([]abstract.Point, 1)
	readList = append(readList, pubKey)
	sb, cerr := cl.WriteTransactionRequest(scurl, encShares, pubKeys, G, H, readList)
	log.ErrFatal(cerr)
	//cl.Close()
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

func getPubKeys(el *onet.Roster) []abstract.Point {

	cl := keypoll.NewClient()
	keys, err := cl.Keypoll(el)
	log.ErrFatal(err)

	size := len(keys)
	for i := 0; i < size/2; i++ {
		tmp := keys[size-i-1]
		keys[size-i-1] = keys[i]
		keys[i] = tmp
	}
	//cl.Close()
	return keys
}

// This function can replace the service for polling
// the servers to collect their public keys.
//
// func readToml(fname *string) {
//
// 	var keys []abstract.Point
// 	fh, _ := os.Open(*fname)
// 	defer fh.Close()
// 	fs := bufio.NewScanner(fh)
//
// 	for fs.Scan() {
// 		tmp, _ := crypto.StringHexToPoint(network.Suite, fs.Text())
// 		keys = append(keys, tmp)
// 	}
//
// 	for i := 0; i < len(keys); i++ {
// 		fmt.Println(keys[i])
// 	}
// }
