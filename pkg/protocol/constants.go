package protocol

const (
	RelayMagic = 0x9E79BC40
)

// Relay Protocol Message Types
const (
	MsgPing               = 0
	MsgPong               = 1
	MsgJoinRelayRequest   = 2
	MsgJoinSessionRequest = 3
	MsgResponse           = 4
	MsgConnectRequest     = 5
	MsgSessionInvitation  = 6
	MsgRelayFull          = 7
)
