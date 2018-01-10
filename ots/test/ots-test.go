package main

import (
	"flag"
	"fmt"
	"os"

	ots "github.com/dedis/cothority_template/ots"
	util "github.com/dedis/cothority_template/ots/util"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func main() {

	numTrusteePtr := flag.Int("t", 0, "size of the SC cothority")
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

	pubKeys, err := ots.GetPubKeys(pkFilePtr)

	if err != nil {
		log.Errorf("Couldn't read pk file: %v", err)
		os.Exit(1)
	}

	dataPVSS, err := ots.SetupPVSS(pubKeys, *numTrusteePtr)

	//TODO: Use symKey to encrypt data
	mesg := "Dunyali dostum, tam olarak anlamadin galiba. KACIRILDIN!"
	log.Info("Plaintext message is:", mesg)
	encMesg, hashEnc := ots.EncryptMessage(dataPVSS, &mesg)

	if err != nil {
		log.Errorf("Could not setup PVSS: %v", err)
		os.Exit(1)
	}

	// Reader's pk/sk pair
	privKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	pubKey := dataPVSS.Suite.Point().Mul(nil, privKey)

	gr := util.GetGroup(*filePtr)
	log.Lvl3(gr)

	scurl, err := ots.CreateSkipchain(gr.Roster)

	if err != nil {
		log.Errorf("Could not create skipchain: %v", err)
		os.Exit(1)
	}

	// Creating write transaction
	sbWrite, err := ots.CreateWriteTransaction(scurl, dataPVSS, hashEnc, pubKey)
	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}

	// Bob gets it from Alice
	writeID := sbWrite.Hash

	// fmt.Println("sbWrite hash is", sbWrite.Hash)
	// fmt.Println("sbWrite fwd len is", sbWrite.GetForwardLen())
	// fmt.Println("sbWrite index is", sbWrite.Index)
	// fmt.Println("sbwrite bcklink", sbWrite.BackLinkIDs[0].Short())

	// Get write transaction from skipchain
	writeTxnData, err := ots.GetWriteTransaction(scurl, writeID)
	if err != nil {
		log.Errorf("Could not retrieve write transaction: %v", err)
		os.Exit(1)
	}

	// Verify encrypted shares

	_, verifiedEncShares, err := pvss.VerifyEncShareBatch(network.Suite, writeTxnData.H, writeTxnData.PublicKeys, writeTxnData.EncProofs, writeTxnData.EncShares)

	if err != nil {
		log.Errorf("Could not verify encrypted shares: %v", err)
		os.Exit(1)
	}

	if len(verifiedEncShares) != len(writeTxnData.EncShares) {
		log.Errorf("Invalid encrypted shares in the write transaction")
		os.Exit(1)
	}

	validHash := ots.VerifyEncMesg(writeTxnData, encMesg)

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
	sbRead, err := ots.CreateReadTransaction(scurl, writeID, privKey)
	// TESTING!
	// sbRead, err := createReadTransaction(scurl, writeID, diffSk)
	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}

	// fmt.Println("sbRead hash is", sbRead.Hash)
	// fmt.Println("sbRead fwd len is", sbRead.GetForwardLen())
	// fmt.Println("sbRead index is", sbRead.Index)
	// fmt.Println("sbread bcklink", sbRead.BackLinkIDs[0].Short())

	// This is carried out by trustees
	// writeID is the hash of the write txn block
	// readID is the hash of the read txn block

	readID := sbRead.Hash

	updWriteBlk, _ := ots.GetUpdatedBlock(scurl, writeID)
	fmt.Println("Forward link is:", updWriteBlk.ForwardLink[0].Hash.Short())

	scPubKeys := sbRead.Roster.Publics()

	ots.TestSkipchain(scurl, dataPVSS)

	decShares, err := ots.GetDecryptShares(scurl, el, writeTxnData.H, scPubKeys, writeTxnData.EncShares, writeTxnData.EncProofs, updWriteBlk, sbRead.Index, sbRead.SkipBlockFix, updWriteBlk.Hash, readID)

	if err != nil {
		log.Errorf("Could not decrypt shares: %v", err)
		os.Exit(1)
	}

	var validKeys []abstract.Point
	var validEncShares []*pvss.PubVerShare
	var validDecShares []*pvss.PubVerShare

	sz := len(decShares)
	for i := 0; i < sz; i++ {
		validKeys = append(validKeys, writeTxnData.PublicKeys[i])
		validEncShares = append(validEncShares, writeTxnData.EncShares[i])
		validDecShares = append(validDecShares, decShares[i])
	}

	recSecret, err := pvss.RecoverSecret(network.Suite, writeTxnData.G, validKeys, validEncShares, validDecShares, dataPVSS.Threshold, dataPVSS.NumTrustee)
	// recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, dataPVSS.G, dataPVSS.PublicKeys, dataPVSS.EncShares, decShares, dataPVSS.Threshold, dataPVSS.NumTrustee)

	if err != nil {
		log.Errorf("Could not recover secret: %v", err)
		os.Exit(1)
	}

	recMesg := ots.DecryptMessage(recSecret, encMesg, writeTxnData, dataPVSS)
	log.Info("Recovered message is:", recMesg)

	// _, msg, _ := network.Unmarshal(sbRead.Data)
	// abbas := msg.(*ocs.DataOCS)
	// fmt.Println(abbas.Read.DataID)
}
