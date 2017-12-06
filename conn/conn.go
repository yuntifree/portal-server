package conn

import (
	"log"
	"net"

	"github.com/yuntifree/portal-server/huawei"
)

//Conn connection for ac and radius
type Conn struct {
	Acip     net.IP
	Acport   int
	ShareKey string
	Timeout  int
}

//Request handle req process
func (c *Conn) Request(userip net.IP) error {
	req := huawei.NewReqInfo(userip, c.ShareKey)
	log.Printf("Request info:%+v", req)
	msg, err := huawei.SendAndRecv(req, c.Acip, c.Acport, c.ShareKey, c.Timeout)
	if err != nil {
		return err
	}
	log.Printf("Request response:%+v", msg)
	return nil
}

//Challenge handle challenge process
func (c *Conn) Challenge(userip net.IP) (id uint16, cha []byte, err error) {
	req := huawei.NewChallenge(userip, c.ShareKey)
	log.Printf("Challenge request:%+v", req)
	msg, err := huawei.SendAndRecv(req, c.Acip, c.Acport, c.ShareKey, c.Timeout)
	if err != nil {
		return 0, nil, err
	}
	err = msg.CheckFor(*req, c.ShareKey)
	if err != nil {
		return 0, nil, err
	}
	log.Printf("Challenge response:%+v", msg)
	cha = msg.Attrs[0].Str
	return msg.Head.ReqIdentifier, cha, nil
}

//Auth handle auth process
func (c *Conn) Auth(userip net.IP, username, passwd, cha []byte, reqid uint16) error {
	req := huawei.NewAuth(userip, c.ShareKey, username, passwd, reqid, cha)
	log.Printf("Auth request:%+v", req)
	msg, err := huawei.SendAndRecv(req, c.Acip, c.Acport, c.ShareKey, c.Timeout)
	if err != nil {
		return err
	}
	err = msg.CheckFor(*req, c.ShareKey)
	if err != nil {
		return err
	}
	return nil
}
