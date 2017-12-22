package service

import (
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/cothority_template/decshare/protocol"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

const ServiceName = "DecshareService"

type DecshareService struct {
	*onet.ServiceProcessor
}

type DecshareRequest struct {
	Roster     *onet.Roster
	EncShares  []*pvss.PubVerShare
	EncProofs  []abstract.Point
	H          abstract.Point
	FwdLink    *skipchain.BlockLink
	ScPubKeys  []abstract.Point
	WriteHash  skipchain.SkipBlockID
	ReadHash   skipchain.SkipBlockID
	ReadBlkHdr *skipchain.SkipBlockFix
	RootIndex  int
}

type DecshareResponse struct {
	DecShares []*pvss.PubVerShare
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

func init() {
	log.Print("init in service")
	onet.RegisterNewService(ServiceName, newDecshareService)
	network.RegisterMessage(&DecshareRequest{})
	network.RegisterMessage(&DecshareResponse{})
}

func (s *DecshareService) DecshareRequest(req *DecshareRequest) (*DecshareResponse, onet.ClientError) {
	log.Lvl3("DecshareRequest received in service")

	childCount := len(req.Roster.List) - 1
	log.Lvl3("Number of childs:", childCount)
	tree := req.Roster.GenerateNaryTreeWithRoot(childCount, s.ServerIdentity())
	// tree := req.Roster.GenerateNaryTreeWithRoot(1, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol(protocol.Name, tree)
	if err != nil {
		return nil, onet.NewClientError(err)
	}

	dcs := pi.(*protocol.ProtocolPVSSDecrypt)
	dcs.H = req.H
	dcs.EncShares = req.EncShares
	dcs.EncProofs = req.EncProofs
	dcs.RootIndex = req.RootIndex
	dcs.FwdLink = req.FwdLink
	dcs.ScPubKeys = req.ScPubKeys
	dcs.ReadHash = req.ReadHash
	dcs.WriteHash = req.WriteHash
	dcs.ReadBlkHdr = req.ReadBlkHdr

	err = pi.Start()

	if err != nil {
		return nil, onet.NewClientError(err)
	}

	resp := &DecshareResponse{
		DecShares: <-pi.(*protocol.ProtocolPVSSDecrypt).DecShares,
	}
	return resp, nil
}

func (s *DecshareService) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Decshare Service received New Protocol event")
	pi, err := protocol.NewProtocol(tn)
	return pi, err
}

func newDecshareService(c *onet.Context) onet.Service {
	s := &DecshareService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	err := s.RegisterHandler(s.DecshareRequest)
	log.Lvl3("Decshare Service registered")
	if err != nil {
		log.ErrFatal(err, "Couldn't register message:")
	}
	return s
}
