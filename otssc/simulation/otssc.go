package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	ots "github.com/dedis/cothority_template/ots"

	"github.com/dedis/cothority_template/ots/util"
	"github.com/dedis/cothority_template/otssc/protocol"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/simul/monitor"
)

// type ProtocolData struct {
// 	PVSSData      *util.DataPVSS
// 	EncMesg       []byte
// 	WriteTxnSB    *skipchain.SkipBlock
// 	WriteTxnData  *util.WriteTxnData
// 	ReadTxnSBF    *skipchain.SkipBlockFix
// 	ACPublicKeys  []abstract.Point
// 	ReaderPrivKey abstract.Scalar
// 	ReadSBIndex int
// }

func init() {
	onet.SimulationRegister("OTS", NewOTSSimulation)
}

type OTSSimulation struct {
	onet.SimulationBFTree
}

func NewOTSSimulation(config string) (onet.Simulation, error) {
	otss := &OTSSimulation{}
	_, err := toml.Decode(config, otss)
	if err != nil {
		return nil, err
	}
	return otss, nil
}

func (otss *OTSSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {

	sc := &onet.SimulationConfig{}
	//TODO: 3rd parameter to CreateRoster is port #
	log.Info("Simulation setup : CreateRoster")
	otss.CreateRoster(sc, hosts, 2000)
	log.Info("Simulation setup : CreateTree")
	err := otss.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	log.Info("Returning from Setup")
	return sc, nil
}

func (otss *OTSSimulation) Node(config *onet.SimulationConfig) error {
	// log.Info("In Node")
	return otss.SimulationBFTree.Node(config)
}

func (otss *OTSSimulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Info("Size is:", size, "rounds:", otss.Rounds)

	// HARD-CODING AC COTHORITY SIZE!
	acSize := 10
	acRoster := onet.NewRoster(config.Roster.List[:acSize])
	scPubKeys := config.Roster.Publics()

	fmt.Println("Tree size is", config.Tree.Size())
	fmt.Println("PubKey size is", len(scPubKeys))

	numTrustee := config.Tree.Size()

	for round := 0; round < otss.Rounds; round++ {
		log.Info("Round:", round)

		create_sc := monitor.NewTimeMeasure("CreateSC")
		scurl, err := ots.CreateSkipchain(acRoster)
		create_sc.Record()

		if err != nil {
			log.Errorf("Could not create skipchain: %v", err)
			os.Exit(1)
		}

		// Transactions with trustee size = 10
		// Total block # = 2 x dummyTxnCount
		// dummyTxnCount := 5
		// prepareDummyDP(scurl, acRoster, dummyTxnCount)
		dataPVSS := util.DataPVSS{
			Suite:        ed25519.NewAES128SHA256Ed25519(false),
			SCPublicKeys: scPubKeys,
			NumTrustee:   numTrustee,
		}

		create_keys := monitor.NewTimeMeasure("CreateKeys")
		wrPrivKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
		wrPubKey := dataPVSS.Suite.Point().Mul(nil, wrPrivKey)
		// Reader's pk/sk pair
		privKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
		pubKey := dataPVSS.Suite.Point().Mul(nil, privKey)
		create_keys.Record()

		setup_pvss := monitor.NewTimeMeasure("SetupPVSS")
		err = ots.SetupPVSS(&dataPVSS, pubKey)
		// dataPVSS, err := ots.SetupPVSS(scPubKeys, numTrustee)
		setup_pvss.Record()

		if err != nil {
			return err
		}

		mesg := "Dunyali dostum, tam olarak anlamadin galiba. KACIRILDIN!"
		log.Info("Plaintext message is:", mesg)

		encry_mesg := monitor.NewTimeMeasure("EncryptMesg")
		encMesg, hashEnc := ots.EncryptMessage(&dataPVSS, &mesg)
		encry_mesg.Record()

		create_wrt_txn := monitor.NewTimeMeasure("CreateWriteTxn")
		writeSB, err := ots.CreateWriteTxn(scurl, &dataPVSS, hashEnc, pubKey, wrPrivKey)
		create_wrt_txn.Record()

		if err != nil {
			log.Errorf("Could not create write transaction: %v", err)
			os.Exit(1)
		}

		// Bob gets it from Alice
		writeID := writeSB.Hash

		// Get write transaction from skipchain
		get_write_txn_sb := monitor.NewTimeMeasure("GetWriteTxnSB")
		writeSB, writeTxnData, txnSig, err := ots.GetWriteTxnSB(scurl, writeID)
		get_write_txn_sb.Record()

		if err != nil {
			log.Errorf("Could not retrieve write transaction block: %v", err)
			os.Exit(1)
		}

		ver_txn_sig := monitor.NewTimeMeasure("VerifyTxnSig")
		sigVerErr := ots.VerifyTxnSignature(writeTxnData, txnSig, wrPubKey)
		ver_txn_sig.Record()

		if sigVerErr != nil {
			log.Errorf("Signature verification failed on the write transaction: %v", sigVerErr)
			os.Exit(1)
		}

		log.Info("Signature verified on the retrieved write transaction")

		ver_enc_mesg := monitor.NewTimeMeasure("VerifyEncMesg")
		validHash := ots.VerifyEncMesg(writeTxnData, encMesg)
		ver_enc_mesg.Record()

		if validHash != 0 {
			os.Exit(1)
		}

		// h, err := util.CreatePointH(network.Suite, pubKey)
		// if err != nil {
		// 	log.Errorf("Could not generate point h: %v", err)
		// 	os.Exit(1)
		// }
		// // Verify encrypted shares
		// ver_enc_shares := monitor.NewTimeMeasure("VerifyEncShares")
		// _, _, err = pvss.VerifyEncShareBatch(network.Suite, h, writeTxnData.SCPublicKeys, writeTxnData.EncProofs, writeTxnData.EncShares)
		// ver_enc_shares.Record()
		//
		// if err != nil {
		// 	log.Errorf("Could not verify encrypted shares in the write transaction: %v", err)
		// 	os.Exit(1)
		// }

		create_read_txn := monitor.NewTimeMeasure("CreateReadTxn")
		readSB, err := ots.CreateReadTxn(scurl, writeID, privKey)
		create_read_txn.Record()

		if err != nil {
			log.Errorf("Could not create read transaction: %v", err)
			os.Exit(1)
		}

		get_upd_wsb := monitor.NewTimeMeasure("GetUpdatedWriteSB")
		updWriteSB, err := ots.GetUpdatedWriteTxnSB(scurl, writeID)
		get_upd_wsb.Record()
		if err != nil {
			log.Errorf("Could not retrieve updated write txn SB: %v", err)
			os.Exit(1)
		}

		acPubKeys := readSB.Roster.Publics()

		fmt.Println("AC Public Keys length:", len(acPubKeys))

		readTxnSBF := readSB.SkipBlockFix

		// protoData := initialOTSSteps(scurl, dataPVSS, encMesg, hashEnc)

		p, err := config.Overlay.CreateProtocol("otssc", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		// GetDecryptedShares call preparation

		log.Info("Write index is:", updWriteSB.Index)
		idx := readSB.Index - updWriteSB.Index - 1
		if idx < 0 {
			return errors.New("Forward-link index is negative")
		}
		inclusionProof := updWriteSB.GetForward(idx)

		if inclusionProof == nil {
			return errors.New("Forward-link does not exist")
		}

		data := &util.OTSDecryptReqData{
			WriteTxnSBF:    updWriteSB.SkipBlockFix,
			ReadTxnSBF:     readTxnSBF,
			InclusionProof: inclusionProof,
			ACPublicKeys:   acPubKeys,
		}

		proto := p.(*protocol.OTSDecrypt)
		proto.DecReqData = data
		proto.RootIndex = 0

		prep_decreq := monitor.NewTimeMeasure("PrepDecReq")
		msg, err := network.Marshal(data)
		if err != nil {
			return err
		}
		sig, err := util.SignMessage(msg, privKey)
		if err != nil {
			return err
		}
		prep_decreq.Record()

		proto.Signature = &sig

		dec_req := monitor.NewTimeMeasure("DecReq")
		go p.Start()
		reencShares := <-proto.DecShares
		dec_req.Record()

		fmt.Println("DecReq:", dec_req.Wall.Value, dec_req.CPU.Value, dec_req.User.Value)

		dec_reenc_shares := monitor.NewTimeMeasure("DecryptReencShares")
		tmpDecShares, err := ots.DHDecrypt(reencShares, scPubKeys, privKey)
		dec_reenc_shares.Record()

		if err != nil {
			return err
		}

		size := len(tmpDecShares)
		decShares := make([]*pvss.PubVerShare, size)

		for i := 0; i < size; i++ {
			decShares[tmpDecShares[i].S.I] = tmpDecShares[i]
		}

		var validKeys []abstract.Point
		var validEncShares []*pvss.PubVerShare
		var validDecShares []*pvss.PubVerShare

		for i := 0; i < size; i++ {
			validKeys = append(validKeys, writeTxnData.SCPublicKeys[i])
			validEncShares = append(validEncShares, writeTxnData.EncShares[i])
			validDecShares = append(validDecShares, decShares[i])
		}

		ver_recons_pvss := monitor.NewTimeMeasure("VerifyandReconstructPVSS")
		recSecret, err := pvss.RecoverSecret(dataPVSS.Suite, writeTxnData.G, validKeys, validEncShares, validDecShares, dataPVSS.Threshold, dataPVSS.NumTrustee)
		ver_recons_pvss.Record()

		if err != nil {
			return err
		}

		dec_mesg := monitor.NewTimeMeasure("DecryptMessage")
		recvMesg := ots.DecryptMessage(recSecret, encMesg, writeTxnData)
		dec_mesg.Record()
		log.Info("Recovered message is:", recvMesg)

	}
	return nil
}

// func prepareDummyDP(scurl *ocs.SkipChainURL, scRoster *onet.Roster, pairCount int) error {
//
// 	scPubKeys := scRoster.Publics()
// 	numTrustee := len(scPubKeys)
// 	dp, err := ots.SetupPVSS(scPubKeys, numTrustee)
// 	if err != nil {
// 		return err
// 	}
// 	return ots.AddDummyTxnPairs(scurl, dp, pairCount)
// }
