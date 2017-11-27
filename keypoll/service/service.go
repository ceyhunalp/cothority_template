package service

import (
	"github.com/dedis/cothority_template/keypoll/protocol"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

const ServiceName = "KeypollService"

type KeypollService struct {
	*onet.ServiceProcessor
}

type KeypollRequest struct {
	Roster *onet.Roster
}

type KeypollResponse struct {
	PublicKeys []abstract.Point
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

func init() {
	log.Print("init in service")
	onet.RegisterNewService(ServiceName, newKeypollService)
	network.RegisterMessage(&KeypollRequest{})
	network.RegisterMessage(&KeypollResponse{})
}

func (s *KeypollService) KeypollRequest(req *KeypollRequest) (*KeypollResponse, onet.ClientError) {
	log.Lvl5("KeypollRequest received in service")
	tree := req.Roster.GenerateNaryTreeWithRoot(1, s.ServerIdentity())
	log.Lvl5("========= Tree generated =========")
	if tree == nil {
		return nil, onet.NewClientErrorCode(ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol(protocol.Name, tree)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	err = pi.Start()
	log.Lvl5("==================== Protocol started =====================")
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	resp := &KeypollResponse{
		PublicKeys: <-pi.(*protocol.KeypollChannelStruct).PublicKeys,
	}
	return resp, nil
}

func (s *KeypollService) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Keypoll Service received New Protocol event")
	pi, err := protocol.NewProtocol(tn)
	return pi, err
}

func newKeypollService(c *onet.Context) onet.Service {
	s := &KeypollService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	err := s.RegisterHandler(s.KeypollRequest)
	log.Lvl3("Keypoll Service registered")
	if err != nil {
		log.ErrFatal(err, "Couldn't register message:")
	}
	return s
}
