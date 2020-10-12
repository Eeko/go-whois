package whois

import (
	"bytes"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"regexp"
)

const (
	stopCharacter = "\r\n"	// what we use as a stop character when sending our domain query
	whoisPort     = 43		// RFC3912
)

// queriedServers keeps track on what servers have been queried so far.
var queriedServers = make(map[string]struct{})



/*
Whois takes a domain name string as an argument, performs a WHOIS query to 
whois.iana.org as described in RFC3912, seeks for references to other 
WHOIS servers and performs similar queries with the same keywords to them 
recursively. 

Returns all lines from the queries as an array.
*/
func Whois(domain string) []string {
	lines := query(domain, "whois.iana.org")
	return lines
}

func query(domain, whoisServer string) []string {
	//whois_server := whoisserver
	whoisAddress := strings.Join([]string{whoisServer, strconv.Itoa(whoisPort)}, ":")
	conn, err := net.Dial("tcp", whoisAddress)

	if err != nil {
		log.Println(err)
		return []string{"No WHOIS Records found"}
	}

	defer conn.Close() // closes the connection once we return from the Whois() block
	conn.Write([]byte(domain))
	conn.Write([]byte(stopCharacter))
	// copy response to a buffer
	var buf bytes.Buffer
	var lines []string
	io.Copy(&buf, conn)
	lines = strings.Split(buf.String(), "\n")
	queriedServers[whoisServer] = struct{}{} // append the server we just queried to the list

	lines = readWhoisResponse(domain, lines) // recursion!

	return lines
}

func readWhoisResponse(domain string, lines []string) []string {
	// check each line for "refer" line
	for i := 0; i < len(lines); i++ {
		// here we have various methods of detecting potential authoritative whois servers
		matched, _ := regexp.MatchString(`(?i)(whois\sserver|^refer|^whois):\s+`, lines[i])
		if matched {
			re := regexp.MustCompile(`(?i)(whois\sserver|^refer|^whois):\s+([A-Za-z.-]+)`)
			submatches := re.FindStringSubmatch(lines[i])
			if (len(submatches) > 0) { // sometimes the whois server field can be empty
				whoisserver := submatches[len(submatches) - 1]
				_, contains := queriedServers[whoisserver] // avoid infinite loops and repeating queries
				if !contains {
					referenceComment := "## Found reference to " + whoisserver
					lines = append(lines, referenceComment)
					referLines := query(domain, whoisserver) 
					lines = append(lines, referLines...)
				}
			}
		}
	}
	return lines
}