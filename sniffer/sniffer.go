package sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

type Sniffer struct {
	inputPcap  *string
	outputPcap *string
	device	*string
}

// TODO 将log变为web的返回值
func (s *Sniffer) InitSniffer() *gopacket.PacketSource {
	// 有输入pcap文件时
	if *s.inputPcap != "" {
		handle, err := pcap.OpenOffline(*s.inputPcap)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("open pcap file \"%s\"\n", *s.inputPcap)
		return gopacket.NewPacketSource(handle, handle.LinkType())
	}

	if *s.device == "" {
		*s.device = autoSelectDev()
		if *s.device == "" {
			log.Fatalln("no device to capture")
		}
	}

	handle, err := pcap.OpenLive(*s.device, 1024*1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}
	if *bpf != "" {
		if err = handle.SetBPFFilter(*bpf); err != nil {
			log.Fatalln("Failed to set BPF filter:", err)
		}
	}
	log.Printf("open live on device \"%s\", bpf \"%s\"\n", *device, *bpf)
	return gopacket.NewPacketSource(handle, handle.LinkType())
}

func (sniffer *Sniffer) StartCapture
