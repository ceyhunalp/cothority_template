package main

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority/skipchain"
	ots "github.com/dedis/cothority_template/ots"
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
	PVSSData     *ots.DataPVSS
	Roster       *onet.Roster
	WriteTxnData *ots.WriteTransactionData
	EncMesg      []byte
	EncShares    []*pvss.PubVerShare
	EncProofs    []abstract.Point
	FwdLink      *skipchain.BlockLink
	ScPubKeys    []abstract.Point
	WriteHash    skipchain.SkipBlockID
	ReadHash     skipchain.SkipBlockID
	ReadBlkHdr   *skipchain.SkipBlockFix
	RootIndex    int
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
	pubKeys := config.Roster.Publics()

	scurl, err := ots.CreateSkipchain(acRoster)
	// scurl, err := ots.CreateSkipchain(config.Roster)

	if err != nil {
		log.Errorf("Could not create skipchain: %v", err)
		os.Exit(1)
	}

	fmt.Println("Tree size is", config.Tree.Size())
	fmt.Println("PubKey size is", len(pubKeys))

	for round := 0; round < otss.Rounds; round++ {
		log.Info("Round:", round)
		protoData := initialPVSSSteps(scurl, pubKeys, config.Tree.Size())
		round := monitor.NewTimeMeasure("round")
		p, err := config.Overlay.CreateProtocol("otssc", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		proto := p.(*protocol.OTSDecrypt)
		proto.H = protoData.PVSSData.H
		proto.EncShares = protoData.EncShares
		proto.EncProofs = protoData.EncProofs
		proto.RootIndex = protoData.RootIndex
		proto.FwdLink = protoData.FwdLink
		proto.ScPubKeys = protoData.ScPubKeys
		proto.ReadHash = protoData.ReadHash
		proto.WriteHash = protoData.WriteHash
		proto.ReadBlkHdr = protoData.ReadBlkHdr

		go p.Start()
		tmpDecShares := <-proto.DecShares

		log.Lvl3("Finished round", round)

		size := len(tmpDecShares)
		decShares := make([]*pvss.PubVerShare, size)

		for i := 0; i < size; i++ {
			decShares[tmpDecShares[i].S.I] = tmpDecShares[i]
		}

		var validKeys []abstract.Point
		var validEncShares []*pvss.PubVerShare
		var validDecShares []*pvss.PubVerShare

		sz := len(decShares)
		for i := 0; i < sz; i++ {
			if decShares != nil {
				validKeys = append(validKeys, protoData.WriteTxnData.PubKeys[i])
				validEncShares = append(validEncShares, protoData.WriteTxnData.EncShares[i])
				validDecShares = append(validDecShares, decShares[i])
			}
		}

		recSecret, err := pvss.RecoverSecret(protoData.PVSSData.Suite, protoData.WriteTxnData.G, validKeys, validEncShares, validDecShares, protoData.PVSSData.Threshold, protoData.PVSSData.NumTrustee)

		if err != nil {
			log.Errorf("Could not recover secret: %v", err)
			os.Exit(1)
		}

		recvMesg := ots.DecryptMessage(recSecret, protoData.EncMesg, protoData.WriteTxnData, protoData.PVSSData)
		log.Info("Recovered message is:", recvMesg)

	}
	return nil
}

func initialPVSSSteps(scurl *ocs.SkipChainURL, pubKeys []abstract.Point, numTrustee int) *ProtocolData {

	startWall := time.Now()
	cpuTimeSys, cpuTimeUser := GetRTime()
	dataPVSS, err := ots.SetupPVSS(pubKeys, numTrustee)
	cpuSysDuration, cpuUserDuration := GetDiffRTime(cpuTimeSys, cpuTimeUser)
	wallDuration := float64(time.Since(startWall)) / 1.0e9

	fmt.Println("SetupPVSS:", wallDuration, cpuSysDuration, cpuUserDuration)
	// for index := 0; index < len(pubKeys); index++ {
	// 	tmp, _ := crypto.PointToStringHex(network.Suite, pubKeys[index])
	// 	fmt.Println(tmp)
	// }

	if err != nil {
		log.Errorf("Could not setup PVSS: %v", err)
		os.Exit(1)
	}
	mesg := "Dunyali dostum, tam olarak anlamadin galiba. KACIRILDIN!"
	log.Info("Plaintext message is:", mesg)
	encMesg, hashEnc := ots.EncryptMessage(dataPVSS, &mesg)
	privKey := dataPVSS.Suite.Scalar().Pick(random.Stream)
	pubKey := dataPVSS.Suite.Point().Mul(nil, privKey)

	startWall = time.Now()
	cpuTimeSys, cpuTimeUser = GetRTime()
	sbWrite, err := ots.CreateWriteTransaction(scurl, dataPVSS, hashEnc, pubKey)
	cpuSysDuration, cpuUserDuration = GetDiffRTime(cpuTimeSys, cpuTimeUser)
	wallDuration = float64(time.Since(startWall)) / 1.0e9

	fmt.Println("CreateWriteTransaction:", wallDuration, cpuSysDuration, cpuUserDuration)

	if err != nil {
		log.Errorf("Could not create write transaction: %v", err)
		os.Exit(1)
	}

	// Get write transaction from skipchain
	startWall = time.Now()
	cpuTimeSys, cpuTimeUser = GetRTime()

	writeTxnData, err := ots.GetWriteTransaction(scurl, sbWrite.Hash)
	if err != nil {
		log.Errorf("Could not retrieve write transaction: %v", err)
		os.Exit(1)
	}

	_, verifiedEncShares, err := pvss.VerifyEncShareBatch(network.Suite, writeTxnData.H, writeTxnData.PubKeys, writeTxnData.EncProofs, writeTxnData.EncShares)

	if err != nil {
		log.Errorf("Could not verify encrypted shares: %v", err)
		os.Exit(1)
	}

	if len(verifiedEncShares) != len(writeTxnData.EncShares) {
		log.Errorf("Invalid encrypted shares in the write transaction")
		os.Exit(1)
	}

	validHash := ots.VerifyEncMesg(writeTxnData, encMesg)

	if validHash != 0 {
		log.Errorf("Invalid hash for encrypted message")
		os.Exit(1)
	}

	cpuSysDuration, cpuUserDuration = GetDiffRTime(cpuTimeSys, cpuTimeUser)
	wallDuration = float64(time.Since(startWall)) / 1.0e9

	fmt.Println("Verify Write Transaction:", wallDuration, cpuSysDuration, cpuUserDuration)

	writeID := sbWrite.Hash
	sbRead, err := ots.CreateReadTransaction(scurl, writeID, privKey)

	if err != nil {
		log.Errorf("Could not create read transaction: %v", err)
		os.Exit(1)
	}

	readID := sbRead.Hash

	updWriteBlk, _ := ots.GetUpdatedBlock(scurl, writeID)
	// fmt.Println("Forward link is:", updWriteBlk.ForwardLink[0].Hash.Short())

	scPubKeys := sbRead.Roster.Publics()

	// for index := 0; index < len(scPubKeys); index++ {
	// 	tmp, _ := crypto.PointToStringHex(network.Suite, scPubKeys[index])
	// 	fmt.Println(tmp)
	// }

	idx := sbRead.Index - updWriteBlk.Index - 1
	if idx < 0 {
		log.Fatal("ForwardLink index is negative")
		os.Exit(1)
	}
	fwdLink := updWriteBlk.GetForward(idx)

	if fwdLink == nil {
		log.Errorf("Forward does not exist")
		os.Exit(1)
	}

	tmp := &ProtocolData{
		PVSSData:     dataPVSS,
		EncMesg:      encMesg,
		WriteTxnData: writeTxnData,
		EncShares:    writeTxnData.EncShares,
		EncProofs:    writeTxnData.EncProofs,
		FwdLink:      fwdLink,
		ScPubKeys:    scPubKeys,
		WriteHash:    updWriteBlk.Hash,
		ReadHash:     readID,
		ReadBlkHdr:   sbRead.SkipBlockFix,
		RootIndex:    0,
	}

	return tmp
}
