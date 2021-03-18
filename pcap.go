package main

import (
	"github.com/google/gopacket/pcap"
	"log"
)

/*
FindAllDevs - return (ifs []Interface, err error)

	Interface:
		type Interface struct {
			Name        string
			Description string
			Flags       uint32
			Addresses   []InterfaceAddress
		}

	InterfaceAddress:
		type InterfaceAddress struct {
			IP        net.IP
			Netmask   net.IPMask
			Broadaddr net.IP
			P2P       net.IP
		}
 */

// autoSelectDev 当未指定网卡名称时，自动选择本机可用网卡
// @Return string 可用网卡名称，当无可用网卡时，返回空字符串""
func autoSelectDev() string {
	// 查询本机设备
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln(err)
	}
	var availableNames []string	 // 可用网卡名称列表
	for _, i := range ifs {
		for _, addr := range i.Addresses {
			if addr.IP.IsLoopback() ||
				addr.IP.IsMulticast() ||
				addr.IP.IsUnspecified() ||
				addr.IP.IsLinkLocalUnicast() {
				continue // 若当前ip不符合可用要求，则继续遍历
			}
			// 一旦ip证明网卡在工作（可用），则将其加入可用列表中，并跳出ip遍历，回到网卡遍历
			availableNames = append(availableNames, i.Name)
			break
		}
	}
	if len(availableNames) > 0 {
		return availableNames[0]
	}
	return ""
}
