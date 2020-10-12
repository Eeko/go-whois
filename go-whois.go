package main

import (
	"fmt"
	"os"
	
	"github.com/eeko/go-whois/pkg/whois"
)

func main() {
	domains := os.Args[1:]
	for _, domain := range domains {
		lines := whois.Whois(domain)
		for _, line := range lines {
			fmt.Println(line)
		}
	}
}