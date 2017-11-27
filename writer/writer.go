package main

import (
	"flag"
	"fmt"

	"github.com/dedis/cothority/skipchain"
	keypoll "github.com/dedis/cothority_template/keypoll/service"
	"github.com/dedis/cothority_template/writer/util"
	ocs "github.com/dedis/onchain-secrets"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1/log"
)

func main() {

	filePtr := flag.String("g", "", "group.toml file for trustees")
	dbgPtr := flag.Int("d", 0, "debug level")
	//tFilePtr := flag.String("t", "", "group.toml file for trustees")
	//cFilePtr := flag.String("c", "", "group.toml file for the cothority")
	flag.Parse()

	log.SetDebugVisible(*dbgPtr)

	pubKeys := getPubKeys(filePtr)

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
	tmpEncShares, _, _ := pvss.EncShares(suite, H, pubKeys, s, t)
	sz := len(tmpEncShares)
	encShares := make([]pvss.PubVerShare, sz)

	for i := 0; i < sz; i++ {
		encShares[i] = *tmpEncShares[i]
	}

	sbWrite := createWriteTransaction(scurl, encShares, pubKeys, G, H, pubKey)
	fmt.Println("sbWrite hash is", sbWrite.Hash)

	dataID := sbWrite.Hash
	sbRead := createReadTransaction(scurl, dataID, privKey)
	fmt.Println("sbRead hash is", sbRead.Hash)

	getWriteTransaction(scurl, sbWrite.Hash)

}

func getWriteTransaction(scurl *ocs.SkipChainURL, dataID skipchain.SkipBlockID) {

	cl := ocs.NewClient()
	writeTxn, err := cl.GetWriteTxnData(scurl, dataID)
	log.ErrFatal(err)
	sz := len(writeTxn.PubKeys)
	for i := 0; i < sz; i++ {
		fmt.Println(writeTxn.PubKeys[i])
	}
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

func getPubKeys(groupToml *string) []abstract.Point {

	fmt.Println(groupToml)
	el, err := util.ReadRoster(*groupToml)
	log.ErrFatal(err, "Couldn't Read File")
	log.Lvl3(el)

	for i := 0; i < len(el.List); i++ {
		fmt.Println(el.List[i])
	}

	cl := keypoll.NewClient()
	keys, err := cl.Keypoll(el)

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
