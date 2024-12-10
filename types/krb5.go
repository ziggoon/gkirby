package types

import (
	"encoding/asn1"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

type KerbProtocolMessageType uint32

const (
	KerbQueryTicketCacheExMessage    KerbProtocolMessageType = 14
	KerbRetrieveEncodedTicketMessage KerbProtocolMessageType = 8
)

// asn.1 structs
// i was really struggling with the asn.1 structs, apparently golang encoding/asn1 package doesnt handle all cases properly
// https://github.com/jcmturner/gokrb5?tab=readme-ov-file#known-issues

// marshalKrbCred holds the raw struct that will be unmarshalled from the asn.1 encoded ticket
type marshalKrbCred struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

// KrbCred is the actual type
type KrbCred struct {
	PVNO             int
	MsgType          int
	Tickets          []Ticket
	EncPart          EncryptedData
	DecryptedEncPart EncKrbCredPart
}

type Ticket struct {
	TktVNO           int32         `asn1:"explicit,tag:0"`
	Realm            string        `asn1:"generalstring,explicit,tag:1"`
	SName            PrincipalName `asn1:"explicit,tag:2"`
	EncPart          EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart `asn1:"optional"`
}

type EncTicketPart struct {
	Flags             asn1.BitString    `asn1:"explicit,tag:0"`
	Key               EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string            `asn1:"generalstring,explicit,tag:2"`
	CName             PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding `asn1:"explicit,tag:4"`
	AuthTime          time.Time         `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time         `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time         `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time         `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:10"`
}

// AuthorizationData implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6
type AuthorizationData []AuthorizationDataEntry

// AuthorizationDataEntry implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6
type AuthorizationDataEntry struct {
	ADType int32  `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

type PrincipalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `ans1:"generalstring,explicit,tag:1"`
}

type EncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo `ans1:"explicit,tag:0"`
	Nonce      int           `ans1:"optional,explicit,tag:1"`
	Timestamp  time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int           `asn1:"optional,explicit,tag:3"`
	SrcAddress HostAddress   `asn1:"optional,explicit,tag:4"`
	DstAddress HostAddress   `asn1:"optional,explicit,tag:5"`
}

type KrbCredInfo struct {
	Key       EncryptionKey  `asn1:"explicit,tag:0"`
	PRealm    string         `asn1:"generalstring,optional,explicit,tag:1"`
	PName     PrincipalName  `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time      `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time      `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string         `ans1:"optional,explicit,ia5,tag:8"`
	SName     PrincipalName  `asn1:"optional,explicit,tag:9"`
	CAddr     HostAddresses  `asn1:"optional,explicit,tag:10"`
}

type EncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type HostAddresses []HostAddress
type HostAddress struct {
	addrType    int32  `asn1:"explicit,tag:0"`
	addressData []byte `asn1:"explicit,tag:1"`
}

type KrbTicket struct {
	StartTime      time.Time
	EndTime        time.Time
	RenewTime      time.Time
	TicketFlags    TicketFlags
	EncryptionType int32
	ServerName     string
	ServerRealm    string
	ClientName     string
	ClientRealm    string
	KrbCred        *KrbCred
}

type KerbQueryTktCacheRequest struct {
	MessageType KerbProtocolMessageType
	_           uint32
	LogonId     windows.LUID
}

type KerbQueryTktCacheResponse struct {
	MessageType    KerbProtocolMessageType
	CountOfTickets uint32
	Tickets        [1]KerbTicketCacheInfoEx
}

type KerbRetrieveTktRequest struct {
	MessageType       KerbProtocolMessageType
	LogonId           windows.LUID
	TargetName        LsaString
	TicketFlags       uint32
	CacheOptions      uint32
	EncryptionType    int32
	CredentialsHandle SecurityHandle
}

type KerbRetrieveTktResponse struct {
	Ticket KerbExternalTicket
}

type KerbExternalTicket struct {
	ServiceName         uintptr
	TargetName          uintptr
	ClientName          uintptr
	DomainName          LsaStringOut
	TargetDomainName    LsaStringOut
	AltTargetDomainName LsaStringOut
	SessionKey          KerbCryptoKey
	TicketFlags         uint32
	Flags               uint32
	KeyExpirationTime   int64
	StartTime           int64
	EndTime             int64
	RenewUntil          int64
	TimeSkew            int64
	EncodedTicketSize   int32
	EncodedTicket       uintptr
}

type KerbCryptoKey struct {
	KeyType int32
	Length  int32
	Value   uintptr
}

type KerbTicketCacheInfoEx struct {
	ClientName     LsaString
	ClientRealm    LsaString
	ServerName     LsaString
	ServerRealm    LsaString
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

func (t TicketFlags) String() string {
	var flags []string

	flagMap := map[TicketFlags]string{
		TicketReserved:         "reserved",
		TicketForwardable:      "forwardable",
		TicketForwarded:        "forwarded",
		TicketProxiable:        "proxiable",
		TicketProxy:            "proxy",
		TicketMayPostdate:      "may_postdate",
		TicketPostdated:        "postdated",
		TicketInvalid:          "invalid",
		TicketRenewable:        "renewable",
		TicketInitial:          "initial",
		TicketPreAuthent:       "pre_authent",
		TicketHWAuthent:        "hw_authent",
		TicketOkAsDelegate:     "ok_as_delegate",
		TicketAnonymous:        "anonymous",
		TicketNameCanonicalize: "name_canonicalize",
	}

	for flag, name := range flagMap {
		if t&flag != 0 {
			flags = append(flags, name)
		}
	}

	if len(flags) == 0 {
		return "empty"
	}

	return strings.Join(flags, ", ")
}
