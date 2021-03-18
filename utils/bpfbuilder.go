package utils

import "encoding/json"

type BPFFilter struct {
	tcpPort []string
	udpPort []string
	srcPort []string
	dstPort []string

}
/*
libpcap使用bpf作为包过滤的一种语法规则，使用winpcap/libpcap作为底层的gopacket也支持这种规则，语法参考：

Berkeley Packet Filter(BPF) Documents:
https://www.ibm.com/support/knowledgecenter/SS42VS_7.4/com.ibm.qradar.doc/c_forensics_bpf.html
https://biot.com/capstats/bpf.html
 */
// BuildBPFFilters 通过前端传过来的json数据建立一个符合bpf语法规则的字符串组，以便添加规则
func BuildBPFFilters(jsonBytes []byte) []string {
	json.Unmarshal(jsonBytes)
	dst port port
}
