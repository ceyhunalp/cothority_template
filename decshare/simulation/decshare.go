package main

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/simul"
	"gopkg.in/dedis/onet.v1/simul/monitor"
)

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
	for round := 0; round < otss.Rounds; round++ {
		round := monitor.NewTimeMeasure("round")
		p, err := config.Overlay.CreateProtocol("Decshare", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		go p.Start()

	}
	return nil
}

func main() {
	simul.Start()
}
