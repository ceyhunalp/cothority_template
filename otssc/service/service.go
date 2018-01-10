package service

import (
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/cothority_template/otssc/protocol"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

const ServiceName = "OTSSCService"

type OTSSCService struct {
	*onet.ServiceProcessor
}

type OTSDecryptReq struct {
	Roster       *onet.Roster
	RootIndex    int
	H            abstract.Point
	SCPublicKeys []abstract.Point
	EncShares    []*pvss.PubVerShare
	EncProofs    []abstract.Point
	FwdLink      *skipchain.BlockLink
	ReadBlkHdr   *skipchain.SkipBlockFix
	WriteHash    skipchain.SkipBlockID
	ReadHash     skipchain.SkipBlockID
}

type OTSDecryptResp struct {
	DecShares []*pvss.PubVerShare
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

func init() {
	log.Print("init in service")
	onet.RegisterNewService(ServiceName, newOTSSCService)
	network.RegisterMessage(&OTSDecryptReq{})
	network.RegisterMessage(&OTSDecryptResp{})
}

func (s *OTSSCService) OTSDecryptReq(req *OTSDecryptReq) (*OTSDecryptResp, onet.ClientError) {
	log.Lvl3("OTSDecryptReq received in service")

	childCount := len(req.Roster.List) - 1
	log.Lvl3("Number of childs:", childCount)
	tree := req.Roster.GenerateNaryTreeWithRoot(childCount, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol(protocol.Name, tree)
	if err != nil {
		return nil, onet.NewClientError(err)
	}

	otsDec := pi.(*protocol.OTSDecrypt)
	otsDec.RootIndex = req.RootIndex
	otsDec.H = req.H
	otsDec.SCPublicKeys = req.SCPublicKeys
	otsDec.EncShares = req.EncShares
	otsDec.EncProofs = req.EncProofs
	otsDec.FwdLink = req.FwdLink
	otsDec.ReadHash = req.ReadHash
	otsDec.WriteHash = req.WriteHash
	otsDec.ReadBlkHdr = req.ReadBlkHdr

	err = pi.Start()

	if err != nil {
		return nil, onet.NewClientError(err)
	}

	resp := &OTSDecryptResp{
		DecShares: <-pi.(*protocol.OTSDecrypt).DecShares,
	}
	return resp, nil
}

func (s *OTSSCService) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("OTSDecrypt Service received New Protocol event")
	pi, err := protocol.NewProtocol(tn)
	return pi, err
}

func newOTSSCService(c *onet.Context) onet.Service {
	s := &OTSSCService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	err := s.RegisterHandler(s.OTSDecryptReq)
	log.Lvl3("OTSSC Service registered")
	if err != nil {
		log.ErrFatal(err, "Couldn't register message:")
	}
	return s
}