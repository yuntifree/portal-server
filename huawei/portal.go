package huawei

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"math"
	"math/rand"
	"net"
	"time"
)

func newMessage(typ byte, userip net.IP, serialNo uint16, reqID uint16) *Message {
	msg := new(Message)
	msg.Head.Version = curVersion
	msg.Head.Type = typ
	msg.Head.SerialNo = serialNo
	msg.Head.ReqIdentifier = reqID
	msg.Head.UserIP = userip.To4()
	msg.Head.Authenticator = make([]byte, 16)
	return msg
}

func newSerialNo() uint16 {
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(math.MaxUint16)
	return uint16(r)
}

//NewChallenge generate challenge message
func NewChallenge(userip net.IP, secret string) *Message {
	msg := newMessage(ReqChallenge, userip, newSerialNo(), 0)
	msg.AuthBy(secret)
	return msg
}

//NewLogout generate logout message
func NewLogout(userip net.IP, secret string) *Message {
	msg := newMessage(ReqLogout, userip, newSerialNo(), 0)
	msg.AuthBy(secret)
	return msg
}

//NewAffAckAuth generate aff ack auth message
func NewAffAckAuth(userip net.IP, secret string, serial, reqid uint16) *Message {
	msg := newMessage(AffAckAuth, userip, serial, reqid)
	msg.AuthBy(secret)
	return msg
}

//NewAuth generate auth message
func NewAuth(userip net.IP, secret string, username []byte, userpwd []byte,
	reqid uint16, cha []byte) *Message {
	msg := newMessage(ReqAuth, userip, newSerialNo(), reqid)
	msg.Head.AttrNum = 3
	hash := md5.New()
	hash.Write([]byte{byte(reqid)})
	hash.Write(userpwd)
	hash.Write(cha)
	cpwd := hash.Sum(nil)
	msg.Attrs = []Attr{
		{Type: byte(1), Len: byte(len(username)), Str: username},
		{Type: byte(3), Len: byte(len(cha)), Str: cha},
		{Type: byte(4), Len: byte(len(cpwd)), Str: cpwd},
	}
	msg.AuthBy(secret)
	return msg
}

//NewReqInfo generate reqinfo message
func NewReqInfo(userip net.IP, secret string) *Message {
	msg := newMessage(ReqInfo, userip, newSerialNo(), 0)
	msg.Head.AttrNum = 2
	msg.Attrs = []Attr{
		{Type: byte(6), Len: 0},
		{Type: byte(7), Len: 0},
	}
	msg.AuthBy(secret)
	return msg
}

//IsResponse check message type
func IsResponse(msg *Message) bool {
	switch msg.Head.Type {
	case AckChallenge, AckAuth, AckLogout, AckInfo:
		return true
	}
	return false
}

//Unmarshal parse buffer to message
func Unmarshal(bts []byte) *Message {
	msg := new(Message)
	buf := bytes.NewBuffer(bts)
	var ipbts [4]byte
	binary.Read(buf, binary.BigEndian, &msg.Head.Version)
	binary.Read(buf, binary.BigEndian, &msg.Head.Type)
	binary.Read(buf, binary.BigEndian, &msg.Head.Pap)
	binary.Read(buf, binary.BigEndian, &msg.Head.Rsv)
	binary.Read(buf, binary.BigEndian, &msg.Head.SerialNo)
	binary.Read(buf, binary.BigEndian, &msg.Head.ReqIdentifier)
	for i := 0; i < 4; i++ {
		binary.Read(buf, binary.BigEndian, &ipbts[i])
	}
	msg.Head.UserIP = net.IPv4(ipbts[0], ipbts[1], ipbts[2], ipbts[3])
	binary.Read(buf, binary.BigEndian, &msg.Head.UserPort)
	binary.Read(buf, binary.BigEndian, &msg.Head.ErrCode)
	binary.Read(buf, binary.BigEndian, &msg.Head.AttrNum)
	var auth [16]byte
	binary.Read(buf, binary.BigEndian, &auth)
	msg.Head.Authenticator = auth[:]
	msg.Attrs = make([]Attr, msg.Head.AttrNum)
	for i := byte(0); i > msg.Head.AttrNum; i++ {
		attr := &msg.Attrs[i]
		binary.Read(buf, binary.BigEndian, &attr.Type)
		binary.Read(buf, binary.BigEndian, &attr.Len)
		attr.Len -= 2
		attr.Str = make([]byte, attr.Len)
		binary.Read(buf, binary.BigEndian, attr.Str)
	}
	return msg
}
