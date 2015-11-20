package client

import (
	"fmt"
	"encoding/hex"
	"github.com/lbarman/prifi/dcnet"
	"github.com/lbarman/crypto/abstract"
	"strconv"
	"github.com/lbarman/prifi/config"
)

// Number of bytes of cell payload to reserve for connection header, length
const socksHeaderLength = 6

type ClientState struct {
	Name				string

	PublicKey			abstract.Point
	privateKey			abstract.Secret

	nClients			int
	nTrustees			int

	PayloadLength		int
	UsablePayloadLength	int
	UseSocksProxy		bool
	
	TrusteePublicKey	[]abstract.Point
	sharedSecrets		[]abstract.Point
	
	CellCoder			dcnet.CellCoder
	
	MessageHistory		abstract.Cipher
}

func newClientState(socksConnId int, nTrustees int, nClients int, payloadLength int, useSocksProxy bool) *ClientState {

	params := new(ClientState)

	params.Name                = "Client-"+strconv.Itoa(socksConnId)
	params.nClients            = nClients
	params.nTrustees           = nTrustees
	params.PayloadLength       = payloadLength
	params.UseSocksProxy       = useSocksProxy

	//prepare the crypto parameters
	rand 	:= config.CryptoSuite.Cipher([]byte(params.Name))
	base	:= config.CryptoSuite.Point().Base()

	//generate own parameters
	params.privateKey       = config.CryptoSuite.Secret().Pick(rand)
	params.PublicKey        = config.CryptoSuite.Point().Mul(base, params.privateKey)

	//placeholders for pubkeys and secrets
	params.TrusteePublicKey = make([]abstract.Point,  nTrustees)
	params.sharedSecrets    = make([]abstract.Point, nTrustees)

	//sets the cell coder, and the history
	params.CellCoder           = config.Factory()
	params.UsablePayloadLength = params.CellCoder.ClientCellSize(payloadLength)

	return params
}

func (clientState *ClientState) printSecrets() {
	//print all shared secrets
	
	fmt.Println("")
	for i:=0; i<clientState.nTrustees; i++ {
		fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		fmt.Println("            TRUSTEE", i)
		d1, _ := clientState.TrusteePublicKey[i].MarshalBinary()
		d2, _ := clientState.sharedSecrets[i].MarshalBinary()
		fmt.Println(hex.Dump(d1))
		fmt.Println("+++")
		fmt.Println(hex.Dump(d2))
	}
	fmt.Println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	fmt.Println("")
}