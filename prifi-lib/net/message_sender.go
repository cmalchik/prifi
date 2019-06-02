package net

import (
	"errors"
	"reflect"
)

// MessageSender is the interface that abstracts the network
// interactions.
type MessageSender interface {
	// SendToClient tries to deliver the message "msg" to the client i.
	SendToClient(i int, msg interface{}) error

	// SendToTrustee tries to deliver the message "msg" to the trustee i.
	SendToTrustee(i int, msg interface{}) error

	// SendToRelay tries to deliver the message "msg" to the relay.
	SendToRelay(msg interface{}) error

	// BroadcastToAllClients tries to deliver the message "msg" to every client, possibly using broadcast.
	BroadcastToAllClients(msg interface{}) error

	// ClientSubscribeToBroadcast should be called by the Clients in order to receive the Broadcast messages.
	// Calling the function starts the handler but does not actually listen for broadcast messages.
	// Sending true to startStopChan starts receiving the broadcasts.
	// Sending false to startStopChan stops receiving the broadcasts.
	ClientSubscribeToBroadcast(clientID int, messageReceived func(interface{}) error, startStopChan chan bool) error
}

/**
 * A wrapper around a messageSender. will automatically print what it does (logFunction) if loggingEnabled, and
 * will call networkErrorHappened on error
 */
type MessageSenderWrapper struct {
	MessageSender
	entity               string
	loggingEnabled       bool
	logSuccessFunction   func(interface{})
	logErrorFunction     func(interface{})
	networkErrorHappened func(error)
}

/**
 * Creates a wrapper around a messageSender. will automatically print what it does (logFunction) if loggingEnabled, and
 * will call networkErrorHappened on error
 */
func NewMessageSenderWrapper(logging bool, logSuccessFunction func(interface{}), logErrorFunction func(interface{}), networkErrorHappened func(error), ms MessageSender) (*MessageSenderWrapper, error) {
	if logging && logSuccessFunction == nil {
		return nil, errors.New("Can't create a MessageSenderWrapper without logFunction if logging is enabled")
	}
	if logging && logErrorFunction == nil {
		return nil, errors.New("Can't create a MessageSenderWrapper without logFunction if logging is enabled")
	}
	if networkErrorHappened == nil {
		return nil, errors.New("Can't create a MessageSenderWrapper without networkErrorHappened. If you don't need error handling, set it to func(e error){}.")
	}
	if ms == nil {
		return nil, errors.New("Can't create a MessageSenderWrapper without messageSender.")
	}

	msw := &MessageSenderWrapper{
		loggingEnabled:       logging,
		entity:               "UnknownSource",
		logSuccessFunction:   logSuccessFunction,
		logErrorFunction:     logErrorFunction,
		networkErrorHappened: networkErrorHappened,
		MessageSender:        ms,
	}

	return msw, nil
}

/**
 * Sets the sending entity, for debugging purposes
 */
func (m *MessageSenderWrapper) SetEntity(e string) {
	m.entity = e
}

/**
 * Send a message to client i. will automatically print what it does (Lvl3) if loggingenabled, and
 * will call networkErrorHappened on error
 */
func (m *MessageSenderWrapper) BroadcastToAllClientsWithLog(msg interface{}, extraInfos string) bool {
	return m.sendToWithLog(m.MessageSender.BroadcastToAllClients, msg, extraInfos)
}

/**
 * Send a message to client i. will automatically print what it does (Lvl3) if loggingenabled, and
 * will call networkErrorHappened on error
 */
func (m *MessageSenderWrapper) SendToClientWithLog(i int, msg interface{}, extraInfos string) bool {
	return m.sendToWithLog2(m.MessageSender.SendToClient, i, msg, extraInfos)
}

/**
 * Send a message to trustee i. will automatically print what it does (Lvl3) if loggingenabled, and
 * will call networkErrorHappened on error
 */
func (m *MessageSenderWrapper) SendToTrusteeWithLog(i int, msg interface{}, extraInfos string) bool {
	return m.sendToWithLog2(m.MessageSender.SendToTrustee, i, msg, extraInfos)
}

/**
 * Send a message to the relay. will automatically print what it does (Lvl3) if loggingenabled, and
 * will call networkErrorHappened on error
 */
func (m *MessageSenderWrapper) SendToRelayWithLog(msg interface{}, extraInfos string) bool {
	return m.sendToWithLog(m.MessageSender.SendToRelay, msg, extraInfos)
}

/**
 * Helper function for both SendToRelay
 */
func (m *MessageSenderWrapper) sendToWithLog(sendingFunc func(interface{}) error, msg interface{}, extraInfos string) bool {
	err := sendingFunc(msg)
	msgName := reflect.TypeOf(msg).String()
	if err != nil {
		e := m.entity + ": Tried to send a " + msgName + ", but some network error occurred. Err is: " + err.Error()
		if m.networkErrorHappened != nil {
			m.networkErrorHappened(errors.New(e))
		}
		if m.loggingEnabled {
			m.logErrorFunction(e + extraInfos)
		}
		return false
	}

	if m.loggingEnabled {
		m.logSuccessFunction(m.entity + ": Sent a " + msgName + "." + extraInfos)
	}
	return true
}

/**
 * Helper function for both SendToClientWithLog and SendToTrusteeWithLog
 */
func (m *MessageSenderWrapper) sendToWithLog2(sendingFunc func(int, interface{}) error, i int, msg interface{}, extraInfos string) bool {
	err := sendingFunc(i, msg)
	msgName := reflect.TypeOf(msg).String()
	if err != nil {
		e := m.entity + ": Tried to send a " + msgName + ", but some network error occurred. Err is: " + err.Error()
		if m.networkErrorHappened != nil {
			m.networkErrorHappened(errors.New(e))
		}
		if m.loggingEnabled {
			m.logErrorFunction(e + extraInfos)
		}
		return false
	}

	if m.loggingEnabled {
		m.logSuccessFunction("Sent a " + msgName + "." + extraInfos)
	}
	return true
}
