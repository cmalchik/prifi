package services

import (
	"fmt"
	"io/ioutil"
	"os"

	prifi_protocol "github.com/dedis/prifi/sda/protocols"
	"gopkg.in/dedis/onet.v2/app"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

var socksClientConfig *prifi_protocol.SOCKSConfig
var socksServerConfig *prifi_protocol.SOCKSConfig

//Set the config, from the prifi.toml. Is called by sda/app.
func (s *ServiceState) SetConfigFromToml(config *prifi_protocol.PrifiTomlConfig) {
	log.Lvl3("Setting PriFi configuration...")
	log.Lvlf3("%+v\n", config)
	s.prifiTomlConfig = config
}

// tryLoad tries to load the configuration and updates if a configuration
// is found, else it returns an error.
func (s *ServiceState) tryLoad() error {
	configFile := s.path + "/identity.bin"
	b, err := ioutil.ReadFile(configFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("Error while reading %s: %s", configFile, err)
	}
	if len(b) > 0 {
		_, msg, err := network.Unmarshal(b, s.Suite())
		if err != nil {
			return fmt.Errorf("Couldn't unmarshal: %s", err)
		}
		log.Lvl3("Successfully loaded")
		s.Storage = msg.(*Storage)
	}
	return nil
}

// mapIdentities reads the group configuration to assign PriFi roles
// to server addresses and returns them with the server
// identity of the relay.
func mapIdentities(group *app.Group) (*network.ServerIdentity, []*network.ServerIdentity) {
	trustees := make([]*network.ServerIdentity, 0)
	var relay *network.ServerIdentity

	// Read the description of the nodes in the config file to assign them PriFi roles.
	nodeList := group.Roster.List
	for i := 0; i < len(nodeList); i++ {
		si := nodeList[i]
		nodeDescription := group.GetDescription(si)

		if nodeDescription == "relay" {
			relay = si
		} else if nodeDescription == "trustee" {
			trustees = append(trustees, si)
		}
	}

	return relay, trustees
}
func (s *ServiceState) setConfigToPriFiProtocol(wrapper *prifi_protocol.PriFiSDAProtocol) {

	//normal nodes only needs the relay in their identity map
	identitiesMap := make(map[string]prifi_protocol.PriFiIdentity)
	identitiesMap[idFromServerIdentity(s.relayIdentity)] = prifi_protocol.PriFiIdentity{
		Role:     prifi_protocol.Relay,
		ID:       0,
		ServerID: s.relayIdentity,
	}
	//but the relay needs to know everyone, and this is managed by the churnHandler
	if s.role == prifi_protocol.Relay {
		identitiesMap = s.churnHandler.createIdentitiesMap()
	}
	//trustees need to know eachother for supertrustee functionality
	//TODO: may not be needed if the supertrustee is configured
	//over the network
	if s.role == prifi_protocol.Trustee {
		for i, v := range s.trusteeIDs {
			identitiesMap[idFromServerIdentity(v)] = prifi_protocol.PriFiIdentity{
				Role:     prifi_protocol.Trustee,
				ID:       i,
				ServerID: v,
			}
		}
	}

	configMsg := &prifi_protocol.PriFiSDAWrapperConfig{
		Toml:       s.prifiTomlConfig,
		Identities: identitiesMap,
		Role:       s.role,
		ClientSideSocksConfig: socksClientConfig,
		RelaySideSocksConfig:  socksServerConfig,
	}

	wrapper.SetConfigFromPriFiService(configMsg)

	//when PriFi-protocol (via PriFi-lib) detects a slow client, call "handleTimeout"
	wrapper.SetTimeoutHandler(s.handleTimeout)
}
