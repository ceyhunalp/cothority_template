package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority/skipchain"
	ots "github.com/dedis/cothority_template/ots"
	"github.com/dedis/cothority_template/ots/util"
	"github.com/dedis/cothority_template/otssc/protocol"
	ocs "github.com/dedis/onchain-secrets"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/simul/monitor"
)

type ProtocolData struct {
	PVSSData      *util.DataPVSS
	EncMesg       []byte
	WriteTxnSB    *skipchain.SkipBlock
	WriteTxnData  *util.WriteTxnData
	ReadTxnSBF    *skipchain.SkipBlockFix
	ACPublicKeys  []abstract.Point
	ReaderPrivKey abstract.Scalar
	// WriterPrivKey abstract.Scalar
	ReadSBIndex int
}

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
	otss.CreateRoster(sc, hosts, 2000)
	err := otss.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (otss *OTSSimulation) Node(config *onet.SimulationConfig) error {
	return otss.SimulationBFTree.Node(config)
}

func (otss *OTSSimulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", otss.Rounds)

	// HARD-CODING AC COTHORITY SIZE!
	acSize := 10
	acRoster := onet.NewRoster(config.Roster.List[:acSize])
	// acPubKeys := acRoster.Publics()
	scPubKeys := config.Roster.Publics()
	// pubKeys := config.Roster.Publics()

	scurl, err := ots.CreateSkipchain(acRoster)

	if err != nil {
		log.Errorf("Could not create skipchain: %v", err)
		os.Exit(1)
	}

	fmt.Println("Tree size is", config.Tree.Size())
	fmt.Println("PubKey size is", len(scPubKeys))

	for round := 0; round < otss.Rounds; round++ {
		log.Info("Round:", round)
		protoData := initialPVSSSteps(scurl, scPubKeys, config.Tree.Size())
		round := monitor.NewTimeMeasure("round")
		p, err := config.Overlay.CreateProtocol("otssc", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		// GetDecryptedShares call preparation
		// index := readSB.Index
		// idx := index - updWriteSB.Index - 1

		idx := protoData.ReadSBIndex - protoData.WriteTxnSB.Index - 1
		if idx < 0 {
			return errors.New("Forward-link index is negative")
		}
		merkleProof := protoData.WriteTxnSB.GetForward(idx)

		if merkleProof == nil {
			return errors.New("Forward-link does not exist")
		}

		data := &util.OTSDecryptReqData{
			WriteTxnSBF:  protoData.WriteTxnSB.SkipBlockFix,
			ReadTxnSBF:   protoData.ReadTxnSBF,
			MerkleProof:  merkleProof,
			ACPublicKeys: protoData.ACPublicKeys,
		}

		proto := p.(*protocol.OTSDecrypt)
		proto.DecReqData = data
		proto.RootIndex = 0

		msg, err := network.Marshal(data)
		if err != nil {
			return err
		}
		sig, err := util.SignMessage(msg, protoData.ReaderPrivKey)
		if err != nil {
			return err
		}

		proto.Signature = &sig

		go p.Start()
		reencShares := <-proto.DecShares

		fmt.Println("Round:", round.CPU.Value, round.User.Value)

		tmpDecShares, err := ots.DHDecrypt(reencShares, scPubKeys, protoData.ReaderPrivKey)
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

		// sz := len(decShares)
		for i := 0; i < size; i++ {
			validKeys = append(validKeys, protoData.WriteTxnData.SCPublicKeys[i])
			validEncShares = append(validEncShares, protoData.WriteTxnData.EncShares[i])
			validDecShares = append(validDecShares, decShares[i])
		}

		recSecret, err := pvss.RecoverSecret(protoData.PVSSData.Suite, protoData.WriteTxnData.G, validKeys, validEncShares, validDecShares, protoData.PVSSData.Threshold, protoData.PVSSData.NumTrustee)

		if err != nil {
			return err
		}

		recvMesg := ots.DecryptMessage(recSecret, protoData.EncMesg, protoData.WriteTxnData, protoData.PVSSData)
		log.Info("Recovered message is:", recvMesg)

	}
	return nil
}

func initialPVSSSteps(scurl *ocs.SkipChainURL, scPubKeys []abstract.Point, numTrustee int) *ProtocolData {

	startWall := time.Now()
	cpuTimeSys, cpuTimeUser := GetRTime()
	dataPVSS, err := ots.SetupPVSS(scPubKeys, numTrustee)
	cpuSysDuration, cpuUserDuration := GetDiffRTime(cpuTimeSys, cpuTimeUser)
	wallDuration := float64(time.Since(startWall)) / 1.0e9

	fmt.Println("SetupPVSS:", wallDuration, cpuSysDuration, cpuUserDuration)

	if err != nil {
		log.Errorf("Could not setup PVSS: %v", err)
		os.Exit(1)
	}

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

	startWall = time.Now()
	cpuTimeSys, cpuTimeUser = GetRTime()
	writeSB, err := ots.CreateWriteTxn(scurl, dataPVSS, hashEnc, pubKey, wrPrivKey)
	cpuSysDuration, cpuUserDuration = GetDiffRTime(cpuTimeSys, cpuTimeUser)
	wallDuration = float64(time.Since(startWall)) / 1.0e9

	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}

	fmt.Println("CreateWriteTxn:", wallDuration, cpuSysDuration, cpuUserDuration)

	// Bob gets it from Alice
	writeID := writeSB.Hash

	// Get write transaction from skipchain
	startWall = time.Now()
	cpuTimeSys, cpuTimeUser = GetRTime()

	writeSB, writeTxnData, sig, err := ots.GetWriteTxnSB(scurl, writeID)
	if err != nil {
		log.Errorf("Could not retrieve write transaction block: %v", err)
		os.Exit(1)
	}

	sigVerErr := ots.VerifyTxnSignature(writeTxnData, sig, wrPubKey)

	if sigVerErr != nil {
		log.Errorf("Signature verification failed on the write transaction: %v", sigVerErr)
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
	_, _, err = pvss.VerifyEncShareBatch(network.Suite, writeTxnData.H, writeTxnData.SCPublicKeys, writeTxnData.EncProofs, writeTxnData.EncShares)

	if err != nil {
		log.Errorf("Could not verify encrypted shares in the write transaction: %v", err)
		os.Exit(1)
	}

	cpuSysDuration, cpuUserDuration = GetDiffRTime(cpuTimeSys, cpuTimeUser)
	wallDuration = float64(time.Since(startWall)) / 1.0e9

	fmt.Println("Verify Write Txn:", wallDuration, cpuSysDuration, cpuUserDuration)

	readSB, err := ots.CreateReadTxn(scurl, writeID, privKey)
	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}

	updWriteSB, err := ots.GetUpdatedWriteTxnSB(scurl, writeID)
	if err != nil {
		log.Errorf("Could not retrieve updated write txn SB: %v", err)
		os.Exit(1)
	}

	acPubKeys := readSB.Roster.Publics()
	scPubKeys = writeTxnData.SCPublicKeys

	readTxnSBF := readSB.SkipBlockFix

	pd := &ProtocolData{
		PVSSData:      dataPVSS,
		EncMesg:       encMesg,
		WriteTxnSB:    updWriteSB,
		WriteTxnData:  writeTxnData,
		ReadTxnSBF:    readTxnSBF,
		ACPublicKeys:  acPubKeys,
		ReaderPrivKey: privKey,
		ReadSBIndex:   readSB.Index,
	}

	return pd
}
