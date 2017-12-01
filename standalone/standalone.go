package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	keypoll "github.com/dedis/cothority_template/keypoll/service"
	"github.com/dedis/cothority_template/writer/util"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	onet "gopkg.in/dedis/onet.v1"
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
	log.ErrFatal(err, "Couldn't Read File")
	log.Lvl3(el)

	pubKeys := getPubKeys(pkFilePtr)

	for i := 0; i < len(pubKeys); i++ {
		fmt.Println(pubKeys[i])
	}

	privKeys := getPrivKeys(el)
	for i := 0; i < len(privKeys); i++ {
		fmt.Println(privKeys[i])
	}

	suite := ed25519.NewAES128SHA256Ed25519(false)
	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

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

	var K []abstract.Point    // good public keys
	var E []*pvss.PubVerShare // good encrypted shares
	var D []*pvss.PubVerShare // good decrypted shares

	for i := 0; i < n; i++ {
		if ds, err := pvss.DecShare(suite, H, pubKeys[i], polyCommits[i], privKeys[i], tmpEncShares[i]); err == nil {
			K = append(K, pubKeys[i])
			E = append(E, tmpEncShares[i])
			D = append(D, ds)
		}
	}

	recSecret, err := pvss.RecoverSecret(suite, G, K, E, D, t, n)

	//
	log.ErrFatal(err)
	//
	G_s := suite.Point().Mul(nil, s)
	fmt.Println("G_s is:\n", G_s)
	fmt.Println("==================")
	fmt.Println("Recovered secret is:\n", recSecret)
}

func getPrivKeys(el *onet.Roster) []abstract.Scalar {

	cl := keypoll.NewClient()
	keys, err := cl.Keypoll(el)
	log.ErrFatal(err)

	size := len(keys)
	for i := 0; i < size/2; i++ {
		tmp := keys[size-i-1]
		keys[size-i-1] = keys[i]
		keys[i] = tmp
	}
	return keys
}

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
