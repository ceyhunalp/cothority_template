package util

import (
	"crypto/sha256"
	"errors"
	"os"

	"gopkg.in/dedis/crypto.v0/abstract"
	onet "gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func SignMessage(msg []byte, privKey abstract.Scalar) (crypto.SchnorrSig, error) {
	tmpHash := sha256.Sum256(msg)
	msgHash := tmpHash[:]
	return crypto.SignSchnorr(network.Suite, privKey, msgHash)
}

func CreatePointH(suite abstract.Suite, pubKey abstract.Point) (abstract.Point, error) {

	binPubKey, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	tmpHash := sha256.Sum256(binPubKey)
	labelHash := tmpHash[:]
	h, _ := suite.Point().Pick(nil, suite.Cipher(labelHash))
	return h, nil
}

func GetGroup(tomlFileName string) *app.Group {
	gr, err := os.Open(tomlFileName)
	log.ErrFatal(err)
	defer gr.Close()
	groups, err := app.ReadGroupDescToml(gr)
	log.ErrFatal(err)
	if groups == nil || groups.Roster == nil || len(groups.Roster.List) == 0 {
		log.Fatal("No servers found in roster from", tomlFileName)
	}
	return groups
}

func ReadRoster(tomlFileName string) (*onet.Roster, error) {
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
