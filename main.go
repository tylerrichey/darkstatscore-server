package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/breml/bpfutils"
	cmap "github.com/orcaman/concurrent-map"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// NetworkData struct to hold captured network data
type NetworkData struct {
	In       int
	Out      int
	LastSeen time.Time
	Mac      Mac
}

var hosts = cmap.New()
var localNetwork = ""

func main() {
	deviceName := flag.String("device", "", "Name of device to capture on. If not provided, lists available devices.")
	listenInfo := flag.String("listen", ":62231", "ip:port to listen on, IP optional")
	localNet := flag.String("localnet", "10.0.0", "First three octets of local network, i.e.: 192.168.1")
	doProfile := flag.Bool("doprof", false, "Enable golang profiling via web interface")
	profileListen := flag.String("proflisten", "localhost:6060", "Profiling web service at specified ip:port")
	flag.Parse()
	if *doProfile {
		go func() {
			fmt.Println(http.ListenAndServe(*profileListen, nil))
		}()
	}

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
		localNetwork = *localNet
		// handle := initHandle(*deviceName)
		afHandle := initAfPacket(*deviceName)
		afHandle2 := initAfPacket(*deviceName)
		afHandle3 := initAfPacket(*deviceName)
		afHandle4 := initAfPacket(*deviceName)
		go processPackets(afHandle)
		go processPackets(afHandle2)
		go processPackets(afHandle3)
		go processPackets(afHandle4)

		for {
			fmt.Println("Listening for connections...")
			if ln, err := net.Listen("tcp4", *listenInfo); err != nil {
				fmt.Println(err.Error())
			} else {
				if conn, err := ln.Accept(); err != nil {
					fmt.Println(err.Error())
				} else {
					fmt.Println("Connection accepted.")

					for {
						bufio.NewReader(conn).ReadString('\n')
						m := make(map[string]NetworkData, len(hosts.Keys()))
						for _, k := range hosts.Keys() {
							h, exists := hosts.Pop(k)
							if exists {
								m[k] = h.(NetworkData)
							}
						}
						b, _ := json.Marshal(&m)
						if _, err := conn.Write(b); err != nil {
							fmt.Println(err.Error())
							break
						}
					}
					ln.Close()
				}
			}
		}
	}
}

func initAfPacket(deviceName string) (handle *afpacket.TPacket) {
	if handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(deviceName),
		afpacket.OptFrameSize(96),
		afpacket.OptBlockSize(12288),
		afpacket.OptNumBlocks(682),
		afpacket.OptPollTimeout(pcap.BlockForever),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3); err != nil {
		panic(err)
	} else {
		filter, _ := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 96, "not (src net "+localNetwork+" and dst net "+localNetwork+")")
		raw := bpfutils.ToBpfRawInstructions(filter)
		handle.SetBPF(raw)
		handle.SetFanout(afpacket.FanoutHashWithDefrag, 4)
		return handle
	}
}

// func initHandle(deviceName string) (handle *pcap.Handle) {
// 	if inactiveHandle, err := pcap.NewInactiveHandle(deviceName); err != nil {
// 		panic(err)
// 	} else {
// 		defer inactiveHandle.CleanUp()
// 		inactiveHandle.SetImmediateMode(true)
// 		inactiveHandle.SetPromisc(true)
// 		inactiveHandle.SetSnapLen(96)
// 		if handle, err := inactiveHandle.Activate(); err != nil {
// 			panic(err)
// 		} else {
// 			handle.SetBPFFilter("not (src net " + localNetwork + " and dst net " + localNetwork + ")")
// 			return handle
// 		}
// 	}
// }

func processPackets(handle *afpacket.TPacket) {
	var (
		eth  layers.Ethernet
		ip4  layers.IPv4
		n    NetworkData
		host string
	)
	startingIP := net.ParseIP(localNetwork + ".1").To4()
	endingIP := net.ParseIP(localNetwork + ".255").To4()
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4)
	decoded := []gopacket.LayerType{}

	for {
		packetData, ci, _ := handle.ZeroCopyReadPacketData()
		parser.DecodeLayers(packetData, &decoded)
		host = ""
		n.LastSeen = ci.Timestamp
		if ipIsBetween(startingIP, endingIP, ip4.DstIP) {
			host = ip4.DstIP.String()
			n.Mac = Mac{eth.DstMAC}
			n.In = ci.Length
			n.Out = 0
		} else {
			host = ip4.SrcIP.String()
			n.Mac = Mac{eth.SrcMAC}
			n.Out = ci.Length
			n.In = 0
		}

		if len(host) > 0 {
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

func ipIsBetween(begin net.IP, end net.IP, trial net.IP) bool {
	return bytes.Compare(trial, begin) >= 0 && bytes.Compare(trial, end) <= 0
}

// MarshalJSON for hardwareaddr
func (m Mac) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.HardwareAddr.String())
}

// Mac used to avoid string allocs
type Mac struct {
	net.HardwareAddr
}
