package main

import (
	"flag"
	"log"
	"net"

	"github.com/enigma522/netcut-cli/networkScan"
)

func main() {


	scanFlag := flag.Bool("scan", false, "Scan the network")
	CIDR := flag.String("cidr", "", "CIDR for the network scan")
	cutFlag := flag.Bool("cut", false, "Cut off a device")
	ipAddr := flag.String("ip", "", "IP address of the device to cut off (required if using cut option)")
	mac := flag.String("mac", "", "MAC address of the device to cut off (required if using cut option)")
	gateway := flag.String("g", "", "Gateway IP address")
	ifaceName := flag.String("i", "wlp49s0", "Interface name")
	flag.Parse()

	scanner := networkscan.NewNetworkScanner(*ifaceName)
	defer scanner.Close()

	if *scanFlag {
		scanner.NetScan(*CIDR) 
	}

	if *cutFlag {
		if *ipAddr == "" {
			log.Fatal("IP address is required when using the cut option.")
		}
		var deviceToCut *networkscan.Device
		if (*mac == "") {
			devices := scanner.NetScan(*ipAddr + "/32") 

			for _, device := range devices {
				if device.IP.String() == *ipAddr {
					deviceToCut = &device
					break
				}
			}
		}else{
			deviceToCut = &networkscan.Device{
				IP:  net.ParseIP(*ipAddr),
				MAC: net.HardwareAddr{},
			}
			macAddr, err := net.ParseMAC(*mac)
			if err != nil {
				log.Fatalf("Error parsing MAC address: %v", err)
			}
			deviceToCut.MAC = macAddr

		}
		if deviceToCut != nil {
			
			log.Printf("Cut off device: IP: %s, MAC: %s, HOSTNAME: %s\n", deviceToCut.IP, deviceToCut.MAC, deviceToCut.HOSTNAME)
			scanner.CutOffDevice(*deviceToCut,*gateway)
		} else {
			log.Printf("Device with IP: %s not found\n", *ipAddr)
		}
	}

}
