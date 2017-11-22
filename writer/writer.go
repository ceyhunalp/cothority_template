package main

import (
	"flag"
	"fmt"

	keypoll "github.com/dedis/cothority_template/keypoll/service"
	"github.com/dedis/cothority_template/writer/util"
	ocs "github.com/dedis/onchain-secrets"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
)

func main() {

	filePtr := flag.String("g", "", "group.toml file for trustees")
	dbgPtr := flag.Int("d", 0, "debug level")
	//tFilePtr := flag.String("t", "", "group.toml file for trustees")
	//cFilePtr := flag.String("c", "", "group.toml file for the cothority")
	flag.Parse()

	log.SetDebugVisible(*dbgPtr)

	pkList := getPubKeys(filePtr)

	for i := 0; i < len(pkList); i++ {
		fmt.Println(pkList[i])
	}

	scurl := createSkipchain(filePtr)
	fmt.Println(scurl.Genesis)

}

func createSkipchain(groupToml *string) *ocs.SkipChainURL {

	gr := util.GetGroup(*groupToml)
	log.Lvl3(gr)

	cl := ocs.NewClient()
	scurl, err := cl.CreateSkipchain(gr.Roster)
	log.ErrFatal(err)
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
	cl.Close()
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
