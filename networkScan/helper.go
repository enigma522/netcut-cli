package networkscan

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}


func SendARPRequest(handle *pcap.Handle, dstMAC net.HardwareAddr ,srcMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer)
	if err != nil {
		log.Println("Error serializing ARP request:", err)
		return
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println("Error sending ARP request:", err)
	}
}

func SendARPReply(handle *pcap.Handle, targetMAC net.HardwareAddr, targetIP net.IP, localMAC net.HardwareAddr, localIP net.IP) {

	ethLayer := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       targetMAC, 
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply, 
		SourceHwAddress:   localMAC,
		SourceProtAddress: localIP,
		DstHwAddress:      targetMAC,
		DstProtAddress:    targetIP,
	}

	// Serialize and send the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer)
	if err != nil {
		log.Println("Error serializing ARP reply:", err)
		return
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Println("Error sending ARP reply:", err)
	}
}



// Helper function to handle ARP replies
func HandleARPPacket(packet gopacket.Packet) Device {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPReply {
			host,_:=net.LookupAddr(net.IP(arp.SourceProtAddress).String())
			return Device{
				IP:  net.IP(arp.SourceProtAddress),
				MAC: net.HardwareAddr(arp.SourceHwAddress),
				HOSTNAME: host,
			}

		}
	}
	return Device{}
}