package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func main() {
	if ifs, err := pcap.FindAllDevs(); err != nil {
		fmt.Print(err)
	} else {
		for _, nif := range ifs {
			fmt.Println(nif.Name)
			for _, net := range nif.Addresses {
				fmt.Println(">", net.IP, "/", net.Netmask)
			}
		}
	}
}
