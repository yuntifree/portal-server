package main

import (
	"context"
	"log"
	"net"

	"github.com/micro/go-micro/client"
	"github.com/yuntifree/portal-server/accounts"
	"github.com/yuntifree/portal-server/huawei"
	verify "github.com/yuntifree/portal-server/proto/verify"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", ":50100")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen failed:%v", err)
	}
	for {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("conn ReadFrom failed:%v", err)
			continue
		}
		log.Printf("remote addr:%v len:%d", addr, n)
		b := buf[:n]
		go handleLogout(b)
	}
}

func handleLogout(buf []byte) {
	msg := huawei.Unmarshal(buf)
	log.Printf("msg:%+v", msg)
	var req verify.LogoutRequest
	req.Ip = msg.Head.UserIP.String()
	cl := verify.NewVerifyClient(accounts.VerifyService, client.DefaultClient)
	_, err := cl.LogoutAck(context.Background(), &req)
	if err != nil {
		log.Printf("LogoutAck failed:%v", err)
	}
}
