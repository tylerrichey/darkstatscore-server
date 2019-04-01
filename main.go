package main

import (
	"bufio"
	"encoding/json"
	"flag"
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

var hosts = cmap.New()
var localNetwork = ""

func main() {
	deviceName := flag.String("device", "", "Name of device to capture on. If not provided, lists available devices.")
	listenInfo := flag.String("listen", ":62231", "ip:port to listen on, IP optional")
	localNet := flag.String("localnet", "10.0.0", "First three octets of local network, i.e.: 192.168.1")
	flag.Parse()
	if len(*deviceName) == 0 {
		fmt.Println("No device name given; showing available devices:")
		if ifs, err := pcap.FindAllDevs(); err != nil {
			fmt.Println(err)
		} else {
			for _, nif := range ifs {
				fmt.Println(nif.Name)
				for _, net := range nif.Addresses {
					fmt.Println(">", net.IP, "/", net.Netmask)
				}
			}
		}
	} else {
		for {
			secondsToWait := 30
			localNetwork = *localNet
			fmt.Println("Listening for connections...")
			ln, _ := net.Listen("tcp4", *listenInfo)
			if conn, err := ln.Accept(); err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println("Connection accepted.")
				go handleCapture(*deviceName)

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
