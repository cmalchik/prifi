package dcnet

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/lbarman/prifi/prifi-lib/config"
	"strconv"
	"crypto/hmac"
	"crypto/sha256"
)

// Relay, Trustee or Client
type DCNET_ENTITY int

const (
	DCNET_CLIENT DCNET_ENTITY = iota
	DCNET_TRUSTEE
	DCNET_RELAY
)

// when enabled, this number of bytes is reserved for the disruption protection
const DISRUPTION_PROTECTION_CONTRIB_LENGTH = 32 // 256 bits reserved for a hash

// A struct with all methods to encode and decode dc-net messages
type DCNetEntity struct {
	//Global for all nodes
	EntityID               int
	Entity                 DCNET_ENTITY
	EquivocationProtectionEnabled bool
	DisruptionProtectionEnabled   bool
	DCNetMessageSize       int
	payloadLength int

	cryptoSuite	 abstract.Suite
	sharedKeys   []abstract.Cipher // keys shared with other DC-net members
	sharedPRNGs  []abstract.Cipher // PRNGs shared with other DC-net members (seeded with sharedKeys)
	currentRound int32

	//Used by the relay
	DCNetRoundDecoder *DCNetRoundDecoder  //nil if unused

	//Equivocation protection
	equivocationProtection *EquivocationProtection //nil if unused
	equivocationContribLength     int //0 if equivocation protection is disabled
}

// DCNetRoundDecoder is used by the relay to decode the dcnet ciphers
type DCNetRoundDecoder struct {
	xorBuffer            []byte
	equivTrusteeContribs [][]byte
	equivClientContribs  [][]byte
}

// Used by clients, trustees
func NewDCNetEntity(
	entityID int,
	entity DCNET_ENTITY,
	DCNetMessageSize int,
	equivocationProtection bool,
	disruptionProtection bool,
		sharedKeys []abstract.Cipher) *DCNetEntity {

	e := new(DCNetEntity)
	e.EntityID = entityID
	e.Entity = entity
	e.DCNetMessageSize = DCNetMessageSize
	e.EquivocationProtectionEnabled = equivocationProtection
	e.DisruptionProtectionEnabled = disruptionProtection
	e.DCNetRoundDecoder = nil
	e.currentRound = 0

	e.cryptoSuite = config.CryptoSuite

	// if the node participates in the DC-net
	if entity != DCNET_RELAY {
		e.sharedKeys = sharedKeys

		// Use the provided shared secrets to seed a pseudorandom DC-nets ciphers shared with each peer.
		keySize := e.cryptoSuite.Cipher(nil).KeySize()
		e.sharedPRNGs = make([]abstract.Cipher, len(sharedKeys))
		for i := range sharedKeys {
			key := make([]byte, keySize)
			sharedKeys[i].Partial(key, key, nil)
			e.sharedPRNGs[i] = e.cryptoSuite.Cipher(key)
		}
	} else {
		e.sharedKeys = make([]abstract.Cipher, 0)
		e.sharedPRNGs = make([]abstract.Cipher, 0)
	}

	// if the equivocation protection is enabled
	if equivocationProtection {
		e.equivocationProtection = NewEquivocation()
		zero := e.equivocationProtection.suite.Scalar().Zero()
		one := e.equivocationProtection.suite.Scalar().One()
		minusOne := e.equivocationProtection.suite.Scalar().Sub(zero, one) //max value
		e.equivocationContribLength = len(minusOne.Bytes())
	}

	// compute the payload size
	e.payloadLength = e.DCNetMessageSize - e.equivocationContribLength
	if e.EquivocationProtectionEnabled {
		e.payloadLength -= DISRUPTION_PROTECTION_CONTRIB_LENGTH
	}

	// make sure we can still encode stuff !
	if e.payloadLength <= 0 {
		panic("DCNet: with those options, the payload length is" + strconv.Itoa(e.payloadLength))
	}

	return e
}

// Encodes "payload" in the correct round. Will skip PRNG material if the round is in the future,
// and crash if the round is in the past or the payload is too long
func (e *DCNetEntity) EncodeForRound(roundID int32, payload []byte) []byte {
	if len(payload) > e.payloadLength {
		panic("DCNet: cannot encode payload of length " + strconv.Itoa(int(len(payload))) + " max length is "+ strconv.Itoa(len(payload)))
	}

	if roundID < e.currentRound {
		panic("DCNet: asked to encode for round " + strconv.Itoa(int(roundID)) + " but we are at  round "+ strconv.Itoa(int(e.currentRound)))
	}

	for e.currentRound < roundID {
		//discard crypto material
		log.Lvl4("DCNet: Discarding round", e.currentRound)

		// consume the PRNGs
		for i := range e.sharedPRNGs {
			dummy := make([]byte, e.payloadLength)
			e.sharedPRNGs[i].XORKeyStream(dummy, dummy)
		}

		e.currentRound++
	}

	var c *DCNetCipher
	if e.Entity == DCNET_CLIENT {
		c = e.clientEncode(payload)
	} else {
		c = e.trusteeEncode()
	}

	return c.ToBytes()
}

func (e *DCNetEntity) computeHmac256(clientID int, message []byte) []byte {
	key := []byte("secret-client-" + strconv.Itoa(clientID))
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

func (e *DCNetEntity) clientEncode(payload []byte) *DCNetCipher {
	c := new(DCNetCipher)

	// pad the payload to the correct size
	if payload == nil {
		payload = make([]byte, e.payloadLength)
	}
	if len(payload) < e.payloadLength {
		payload2 := make([]byte, e.payloadLength)
		copy(payload2[0:len(payload)], payload)
		payload = payload2
	}

	// prepare the pads
	p_ij := make([][]byte, len(e.sharedPRNGs))
	for i := range p_ij {
		p_ij[i] = make([]byte, e.payloadLength)
		e.sharedPRNGs[i].XORKeyStream(p_ij[i], p_ij[i])
	}

	// DC-net encrypt the payload
	c.payload = payload // plaintext
	for i := range p_ij {
		for k := range payload {
			payload[k] ^= p_ij[i][k] // XORs in the pads
		}
	}

	// if the disruption protection is enabled, add a hmac
	if e.DisruptionProtectionEnabled {
		c.disruptionProtectionTag = e.computeHmac256(e.EntityID, c.payload)
	}

	// if the equivocation protection is enabled, encrypt the payload, and add the tag
	if e.EquivocationProtectionEnabled {
		payload, sigma_j := e.equivocationProtection.ClientEncryptPayload(payload, p_ij)
		c.payload = payload // replace the payload with the encrypted version
		c.equivocationProtectionTag = sigma_j
	}

	return c
}

func (e *DCNetEntity) trusteeEncode() *DCNetCipher {
	c := new(DCNetCipher)

	c.payload = make([]byte, e.payloadLength)

	// prepare the pads
	p_ij := make([][]byte, len(e.sharedPRNGs))
	for i := range p_ij {
		p_ij[i] = make([]byte, e.payloadLength)
		e.sharedPRNGs[i].XORKeyStream(p_ij[i], p_ij[i])
	}

	// DC-net encrypt the payload
	for i := range p_ij {
		for k := range c.payload {
			c.payload[k] ^= p_ij[i][k] // XORs in the pads
		}
	}

	// if the equivocation protection is enabled, encrypt the payload, and add the tag
	if e.EquivocationProtectionEnabled {
		sigma_j := e.equivocationProtection.TrusteeGetContribution(p_ij)
		c.equivocationProtectionTag = sigma_j
	}

	return c
}