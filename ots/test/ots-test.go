package main

import (
	"flag"
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

	// Writer's pk/sk pair
	wrPrivKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	wrPubKey := dataPVSS.Suite.Point().Mul(nil, wrPrivKey)

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

	// ots.TestSkipchain(scurl, dataPVSS)

	// Creating write transaction
	writeSB, err := ots.CreateWriteTxn(scurl, dataPVSS, hashEnc, pubKey, wrPrivKey)
	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}

	// Bob gets it from Alice
	writeID := writeSB.Hash

	// Get write transaction from skipchain
	writeSB, writeTxnData, sig, err := ots.GetWriteTxnSB(scurl, writeID)
	if err != nil {
		log.Errorf("Could not retrieve write transaction block: %v", err)
		os.Exit(1)
	}

	// writeTxnData.ReaderPk = wrPubKey
	sigVerErr := ots.VerifyTxnSignature(writeTxnData, sig, wrPubKey)

	if sigVerErr != nil {
		log.Error("Signature verification failed on the write transaction")
		os.Exit(1)
	}

	log.Info("Signature verified on the retrieved write transaction")

	validHash := ots.VerifyEncMesg(writeTxnData, encMesg)

	if validHash == 0 {
		log.Info("Valid hash for encrypted message")
	} else {
		log.Errorf("Invalid hash for encrypted message")
		os.Exit(1)
	}

	// Verify encrypted shares
	_, _, err = pvss.VerifyEncShareBatch(network.Suite, writeTxnData.H, writeTxnData.PublicKeys, writeTxnData.EncProofs, writeTxnData.EncShares)

	if err != nil {
		log.Errorf("Could not verify encrypted shares in the write transaction: %v", err)
		os.Exit(1)
	}

	// if len(verifiedEncShares) != len(writeTxnData.EncShares) {
	// 	log.Errorf("Invalid encrypted shares in the write transaction")
	// 	os.Exit(1)
	// }

	// diffSk := dataPVSS.Suite.Scalar().Pick(random.Stream)
	// diffPk := dataPVSS.Suite.Point().Mul(nil, diffSk)
	// sbWriteDiff, _ := createWriteTxn(scurl, dataPVSS, diffPk)
	// fmt.Println("sbWriteDiff hash is", sbWriteDiff.Hash)

	// Creating read transaction
	readSB, err := ots.CreateReadTxn(scurl, writeID, privKey)
	// TESTING!
	// sbRead, err := createReadTxn(scurl, writeID, diffSk)
	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}

	// writeID is the hash of the write txn block
	// readID is the hash of the read txn block
	// log.Info("In client read txn:", readSB.Hash)

	updWriteSB, _ := ots.GetUpdatedWriteTxnSB(scurl, writeID)
	acPubKeys := readSB.Roster.Publics()
	scPubKeys := writeTxnData.PublicKeys
	// ots.TestSkipchain(scurl, dataPVSS)
	// diffSk := dataPVSS.Suite.Scalar().Pick(random.Stream)

	decShares, err := ots.GetDecryptShares(scurl, el, updWriteSB, readSB.SkipBlockFix, acPubKeys, scPubKeys, privKey, readSB.Index)

	// decShares, err := ots.GetDecryptShares(scurl, el, h, acPubKeys, encShares, encProofs, writeBlk, index, readBlkHdr, writeHash, readHash, scPubKeys, privKey)
	// decShares, err := ots.GetDecryptShares(scurl, el, writeTxnData.H, acPubKeys, writeTxnData.EncShares, writeTxnData.EncProofs, updWriteBlk, sbRead.Index, sbRead.SkipBlockFix, updWriteBlk.Hash, readID, writeTxnData.PublicKeys, privKey)

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
