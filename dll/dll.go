package dll

import "golang.org/x/sys/windows"

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
	DuplicateToken                 = advapi32.NewProc("DuplicateToken")
	RevertToSelf                   = advapi32.NewProc("RevertToSelf")
)
