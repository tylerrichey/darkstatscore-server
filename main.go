package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	cmap "github.com/orcaman/concurrent-map"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// NetworkData struct to hold captured network data
type NetworkData struct {
	In       int
	Out      int
	Mac      string
	LastSeen time.Time
}

const localNetwork string = "10.0.0"

var hosts = cmap.New()

func main() {
	// if ifs, err := pcap.FindAllDevs(); err != nil {
	// 	fmt.Print(err)
	// } else {
	// 	for _, nif := range ifs {
	// 		fmt.Println(nif.Name)
	// 		for _, net := range nif.Addresses {
	// 			fmt.Println(">", net.IP, "/", net.Netmask)
	// 		}
	// 	}
	// }

	for {
		secondsToWait := 30
		fmt.Println("Listening for connections...")
		ln, _ := net.Listen("tcp4", ":62231")
		if conn, err := ln.Accept(); err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("Connection accepted.")
			go handleCapture("\\Device\\NPF_{B841A3AF-0477-4D68-8DBC-FD17EA333A98}")

			for {
				conn.SetReadDeadline(time.Now().Add(time.Duration(secondsToWait) * time.Second))
				msg, _ := bufio.NewReader(conn).ReadString('\n')
				if len(msg) > 0 {
					if input, err := strconv.ParseInt(strings.ReplaceAll(msg, "\n", ""), 0, 32); err == nil && input > 0 {
						secondsToWait = int(input)
					} else if err != nil {
						fmt.Println(err.Error())
					}
					fmt.Println("Update frequency: " + strconv.Itoa(secondsToWait))
					continue
				}
				m := make(map[string]NetworkData)
				for _, k := range hosts.Keys() {
					h, exists := hosts.Pop(k)
					if exists {
						m[k] = h.(NetworkData)
					}
				}
				b, _ := json.Marshal(m)
				if _, err := conn.Write(b); err != nil {
					fmt.Println(err.Error())
					break
				}
			}
		}
	}
}

func handleCapture(deviceName string) {
	if handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("not (src net " + localNetwork + " and dst net " + localNetwork + ")"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	var n NetworkData
	var host string
	var ci = packet.Metadata().CaptureInfo
	n.LastSeen = ci.Timestamp
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		var dstMac = eth.DstMAC.String()
		var srcMac = eth.SrcMAC.String()

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			var srcIP = ip.SrcIP.String()
			var dstIP = ip.DstIP.String()
			if strings.HasPrefix(dstIP, localNetwork) {
				host = dstIP
				n.Mac = dstMac
				n.In = ci.Length
			} else {
				host = srcIP
				n.Mac = srcMac
				n.Out = ci.Length
			}

			hosts.Upsert(host, n, func(exists bool, valueInMap interface{}, newValue interface{}) interface{} {
				nv := newValue.(NetworkData)
				if !exists {
					return nv
				}
				res := valueInMap.(NetworkData)
				res.In += nv.In
				res.Out += nv.Out
				res.LastSeen = nv.LastSeen
				return res
			})
		}
	}
}
