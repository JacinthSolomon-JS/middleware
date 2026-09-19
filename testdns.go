package main

import (
	"fmt"

	"github.com/miekg/dns"
)

func main() {
	client := new(dns.Client)

	message := new(dns.Msg)
	message.SetQuestion("x89a1zq98lbz19q7m3.biz.", dns.TypeA)

	response, _, err := client.Exchange(message, "127.0.0.1:1053")
	if err != nil {
		fmt.Println("DNS request failed:", err)
		return
	}

	fmt.Println("DNS request successful!")
	fmt.Println(response)
}
