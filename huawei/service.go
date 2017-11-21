package huawei

import (
	"fmt"
	"log"
	"net"
	"time"
)

//SendAndRecv send request message and recv response message
func SendAndRecv(msg *Message, dest net.IP, port int, secret string, timeout int) (*Message, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.String(), port))
	if err != nil {
		log.Printf("SendAndRecv ResoveUDPAddr failed:%s %v", dest.String(), err)
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("SendAndRecv DialUDP failed:%+v %v", addr, err)
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	_, err = conn.Write(msg.Bytes())
	if err != nil {
		log.Printf("SendAndRecv Write failed:%v", err)
		return nil, err
	}
	var buf [1024]byte
	n, err := conn.Read(buf[0:])
	if err != nil {
		log.Printf("SendAndRecv Read failed:%v", err)
		return nil, err
	}
	m := Unmarshal(buf[0:n])
	return m, nil
}
