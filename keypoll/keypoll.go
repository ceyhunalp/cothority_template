package main

import (
	"errors"
	"fmt"
	"os"

	serv "github.com/dedis/cothority_template/keypoll/service"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"

	"gopkg.in/urfave/cli.v1"
)

/*
type WriteTxn struct {
	// EncShares   []*pvss.PubVerShare
	EncShares []pvss.PubVerShare
	//Commitments []abstract.Point
	//G           abstract.Point
}
*/

func main() {

	cliApp := cli.NewApp()
	cliApp.Name = "Keypoll"
	cliApp.Usage = "Poll all servers for their pk"

	cliApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "group, g",
			Value: "group.toml",
			Usage: "Cothority group definition in `FILE.toml`",
		},
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: `integer`: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:  "port, p",
			Value: "15000",
			Usage: "Port number",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.GlobalInt("debug"))
		return nil
	}

	cliApp.Action = func(c *cli.Context) error {
		//log.SetUseColors(false)
		//log.SetDebugVisible(c.GlobalInt("debug"))
		return cmdKeypoll(c)
	}
	cliApp.Run(os.Args)
}

func cmdKeypoll(c *cli.Context) error {
	log.Info("Keypoll command")
	groupToml := c.GlobalString("g")
	//port := c.GlobalString("p")
	//addr := "localhost:" + port

	el, err := readRoster(groupToml)
	log.ErrFatal(err, "Couldn't Read File")
	log.Lvl3(el)

	for i := 0; i < len(el.List); i++ {
		fmt.Println(el.List[i])
	}

	cl := serv.NewClient()
	resp, err := cl.Keypoll(el)

	size := len(resp)
	for i := 0; i < size/2; i++ {
		tmp := resp[size-i-1]
		resp[size-i-1] = resp[i]
		resp[i] = tmp
	}

	fmt.Println(resp)
	//createWriteTransaction(resp, addr)

	return nil
}

/*
func startCommunication(txn WriteTxn, addr string) error {

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return errors.New("Error dialing " + addr + " : " + err.Error())
	}

	//gob.Register(abstract.BinaryEncoding{})
	enc := gob.NewEncoder(conn)
	err = enc.Encode(txn)
	if err != nil {
		return errors.New("Encode failed for WriteTxn: " + err.Error())
	}

	conn.Close()

	return nil
}

func createWriteTransaction(pubKeys []abstract.Point, addr string) error {

	suite := ed25519.NewAES128SHA256Ed25519(false)
	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))
	n := 6
	t := 2*n/3 + 1

	// x := make([]abstract.Scalar, n)
	// X := make([]abstract.Point, n)
	//
	// for i := 0; i < n; i++ {
	// 	x[i] = suite.Scalar().Pick(random.Stream)
	// 	X[i] = suite.Point().Mul(nil, x[i])
	// }

	// Generate scalar of shared secret (s)

	s := suite.Scalar().Pick(random.Stream)

	// Generate encrypted shares

	tmpEncShares, pubPoly, _ := pvss.EncShares(suite, H, pubKeys, s, t)

	// Verify encrypted shares

	evalCommits := make([]abstract.Point, n)

	for i := 0; i < n; i++ {
		evalCommits[i] = pubPoly.Eval(tmpEncShares[i].S.I).V
	}

	sz := len(tmpEncShares)

	encShares := make([]pvss.PubVerShare, sz)

	for i := 0; i < sz; i++ {
		encShares[i] = *tmpEncShares[i]
	}

	txn := WriteTxn{EncShares: encShares}
	//txn := WriteTxn{EncShares: encShares, Commitments: evalCommits}
	//txn := WriteTxn{EncShares: encShares, Commitments: evalCommits, G: G}

	fmt.Println("G value in keypoll.go is ", G)
	startCommunication(txn, addr)

	//validKeys, validShares, errEncVerif := pvss.VerifyEncShareBatch(suite, H, pubKeys, evalCommits, encShares)

	//fmt.Println(validKeys, validShares, errEncVerif, G)
	// Check error here

	// Decrypt shares

		// for i := 0; i < n; i++ {
		// 	decShare, err := pvss.DecShare(suite, H, pubKeys, evalCommits, x, encShare)
    //
		// }

	return nil
}
*/

func readRoster(tomlFileName string) (*onet.Roster, error) {
	log.Print("Reading From File")
	f, err := os.Open(tomlFileName)
	if err != nil {
		return nil, err
	}
	el, err := app.ReadGroupToml(f)
	if err != nil {
		return nil, err
	}
	if len(el.List) <= 0 {
		return nil, errors.New("Empty or invalid group file:" +
			tomlFileName)
	}
	log.Lvl3(el)
	return el, err
}
