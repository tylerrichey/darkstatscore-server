package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
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
		for {
			secondsToWait := 10
			localNetwork = *localNet
			fmt.Println("Listening for connections...")
			if ln, err := net.Listen("tcp4", *listenInfo); err != nil {
				fmt.Println(err.Error())
			} else {
				if conn, err := ln.Accept(); err != nil {
					fmt.Println(err.Error())
				} else {
					fmt.Println("Connection accepted.")
					handle := initHandle(*deviceName)
					go processPackets(handle)
					// var lastCaptureSent = time.Now()

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
							// conn.Write([]byte(lastCaptureSent.Format(time.RFC3339)))
						}
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
						// lastCaptureSent = time.Now()
					}
					ln.Close()
				}
			}
		}
	}
}

func initHandle(deviceName string) (handle *pcap.Handle) {
	if inactiveHandle, err := pcap.NewInactiveHandle(deviceName); err != nil {
		panic(err)
	} else {
		defer inactiveHandle.CleanUp()
		// inactiveHandle.SetImmediateMode(true)
		inactiveHandle.SetTimeout(pcap.BlockForever)
		inactiveHandle.SetPromisc(true)
		inactiveHandle.SetSnapLen(96)
		if handle, err := inactiveHandle.Activate(); err != nil {
			panic(err)
		} else {
			handle.SetBPFFilter("not (src net " + localNetwork + " and dst net " + localNetwork + ")")
			return handle
		}
	}
}

func processPackets(handle *pcap.Handle) {
	var (
		eth   layers.Ethernet
		ip4   layers.IPv4
		n     NetworkData
		host  string
		dstIP string
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4)
	decoded := []gopacket.LayerType{}

	for {
		packetData, ci, _ := handle.ZeroCopyReadPacketData()
		parser.DecodeLayers(packetData, &decoded)
		host = ""
		n.LastSeen = ci.Timestamp
		dstIP = ip4.DstIP.String()
		if strings.HasPrefix(dstIP, localNetwork) {
			host = dstIP
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

// MarshalJSON for hardwareaddr
func (m Mac) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.HardwareAddr.String())
}

// Mac used to avoid string allocs
type Mac struct {
	net.HardwareAddr
}
