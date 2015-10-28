package main

import (
	"flag"
	"fmt"
	"time"

	// "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)


func main() {
	filter := flag.String("filter", "true", "pcap filter")
	flag.Parse()

	fullFilter := fmt.Sprintf("( %s ) and ( tcp[32:4] = 0x504f5354 or tcp[32:4] = 0x48545450 )", *filter)
	// look for packets where the first four bytes are either "POST" or "HTTP".

	fmt.Println("Capturing packets with filter : ", fullFilter)
	if handle, err := pcap.OpenLive("eth0", 80, false, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(fullFilter); err != nil {  // optional
		panic(err)
	} else {

		var timings = map[[12]byte]time.Time{}
		for true {
			data, ci, err := handle.ZeroCopyReadPacketData()
			// srcPort := data[34]  + data[35] >> 8
			// dstPort := data[36]  + data[37] >> 8

			var stream [12]byte



			if err == nil {
				if data[66] == 80 {
					// request
					copyArr(&stream, data, 0, 26, 8)
					copyArr(&stream, data, 8, 34, 4)
					timings[stream] = ci.Timestamp
				} else {
					// response
					copyArr(&stream, data, 0, 30, 4)
					copyArr(&stream, data, 4, 26, 4)
					copyArr(&stream, data, 8, 36, 2)
					copyArr(&stream, data, 10, 34, 2)
					if start, ok := timings[stream]; ok {
						fmt.Printf("%v %v %v\n", stream, start, float64(ci.Timestamp.Sub(start).Nanoseconds()/1000)/1000)
					} else {
						fmt.Println("Missed Req for Res", stream)
					}
				}
			}
		}
	}
}

func copyArr(dst *[12]byte, src []byte, dstStart, srcStart, len int) {
	for i := 0 ; i < len; i++ {
		dst[dstStart + i] = src[srcStart + i]
	}
}
