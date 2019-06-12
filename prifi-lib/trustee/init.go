package trustee

import (
	"errors"
	"github.com/dedis/prifi/prifi-lib/crypto"
	"github.com/dedis/prifi/prifi-lib/dcnet"
	"github.com/dedis/prifi/prifi-lib/net"
	"github.com/dedis/prifi/prifi-lib/scheduler"
	"github.com/dedis/prifi/prifi-lib/utils"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2/log"
	"reflect"
	"strings"
)

// Possible sending rates for the trustees.
const (
	TRUSTEE_KILL_SEND_PROCESS int16 = iota // kills the goroutine responsible for sending messages
	TRUSTEE_RATE_ACTIVE
	TRUSTEE_RATE_HALVED
)

// PriFiLibTrusteeInstance contains the mutable state of a PriFi entity.
type PriFiLibTrusteeInstance struct {
	messageSender *net.MessageSenderWrapper
	trusteeState  *TrusteeState
	stateMachine  *utils.StateMachine
}

// NewPriFiClientWithState creates a new PriFi client entity state.
func NewTrustee(neverSlowDown bool, alwaysSlowDown bool, baseSleepTime int, msgSender *net.MessageSenderWrapper) *PriFiLibTrusteeInstance {

	trusteeState := new(TrusteeState)

	//init the static stuff
	trusteeState.sendingRate = make(chan int16, 10)
	trusteeState.PublicKey, trusteeState.privateKey = crypto.NewKeyPair()
	neffShuffle := new(scheduler.NeffShuffle)
	neffShuffle.Init()
	trusteeState.neffShuffle = neffShuffle.TrusteeView
	trusteeState.NeverSlowDown = neverSlowDown
	trusteeState.AlwaysSlowDown = alwaysSlowDown

	if neverSlowDown && alwaysSlowDown {
		log.Fatal("Cannot have alwaysSlowDown=true && neverSlowDown=true")
	}

	trusteeState.BaseSleepTime = baseSleepTime

	//init the state machine
	states := []string{"BEFORE_INIT", "INITIALIZING", "SHUFFLE_DONE", "READY", "BLAMING", "SHUTDOWN"}
	sm := new(utils.StateMachine)
	logFn := func(s interface{}) {
		log.Lvl3(s)
	}
	errFn := func(s interface{}) {
		if strings.Contains(s.(string), ", but in state SHUTDOWN") { //it's an "acceptable error"
			log.Lvl2(s)
		} else {
			log.Fatal(s)
		}
	}
	sm.Init(states, logFn, errFn)

	prifi := PriFiLibTrusteeInstance{
		messageSender: msgSender,
		trusteeState:  trusteeState,
		stateMachine:  sm,
	}
	return &prifi
}

// TrusteeState contains the mutable state of the trustee.
type TrusteeState struct {
	DCNet                         *dcnet.DCNetEntity
	ClientPublicKeys              []kyber.Point
	ID                            int
	MessageHistory                kyber.XOF
	Name                          string
	nClients                      int
	neffShuffle                   *scheduler.NeffShuffleTrustee
	nTrustees                     int
	PayloadSize                   int
	privateKey                    kyber.Scalar
	PublicKey                     kyber.Point
	sendingRate                   chan int16
	sharedSecrets                 []kyber.Point
	TrusteeID                     int
	BaseSleepTime                 int
	AlwaysSlowDown                bool //enforce the sleep in the sending function even if rate is FULL
	NeverSlowDown                 bool //ignore the sleep in the sending function if rate is STOPPED
	EquivocationProtectionEnabled bool
	SupertrusteeEnabled           bool
	bufferedCiphers               map[int32]map[int][]byte
}

// NeffShuffleResult holds the result of the NeffShuffle,
// since it needs to be verified when we receive REL_TRU_TELL_TRANSCRIPT.
type NeffShuffleResult struct {
	base  kyber.Point
	pks   []kyber.Point
	proof []byte
}

// ReceivedMessage must be called when a PriFi host receives a message.
// It takes care to call the correct message handler function.
func (p *PriFiLibTrusteeInstance) ReceivedMessage(msg interface{}) error {

	var err error

	switch typedMsg := msg.(type) {
	case net.ALL_ALL_PARAMETERS:
		if typedMsg.ForceParams || p.stateMachine.AssertState("BEFORE_INIT") {
			err = p.Received_ALL_ALL_PARAMETERS(typedMsg) //todo change this name
		}
	case net.ALL_ALL_SHUTDOWN:
		err = p.Received_ALL_ALL_SHUTDOWN(typedMsg)
	case net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE:
		if p.stateMachine.AssertState("INITIALIZING") {
			err = p.Received_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE(typedMsg)
		}
	case net.REL_TRU_TELL_TRANSCRIPT:
		if p.stateMachine.AssertState("SHUFFLE_DONE") {
			err = p.Received_REL_TRU_TELL_TRANSCRIPT(typedMsg)
		}
	case net.REL_TRU_TELL_RATE_CHANGE:
		if p.stateMachine.AssertState("READY") {
			err = p.Received_REL_TRU_TELL_RATE_CHANGE(typedMsg)
		}
	case net.REL_ALL_DISRUPTION_REVEAL:
		if p.stateMachine.AssertState("READY") {
			log.Fatal("not implemented")
			//err = p.Received_REL_ALL_REVEAL(typedMsg)
		}
	case net.REL_ALL_DISRUPTION_SECRET:
		if p.stateMachine.AssertState("BLAMING") {
			log.Fatal("not implemented")
			//err = p.Received_REL_ALL_SECRET(typedMsg)
		}
	case net.TRU_REL_DC_CIPHER:
		if p.stateMachine.AssertState("READY") {
			err = p.Received_TRU_REL_DC_CIPHER(typedMsg)
		}
	default:
		err = errors.New("Unrecognized message, type" + reflect.TypeOf(msg).String())
	}

	return err
}
