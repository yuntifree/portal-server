package huawei

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	curVersion   = 0x02
	ReqChallenge = iota
	AckChallenge
	ReqAuth
	AckAuth
	ReqLogout
	AckLogout
	AffAckAuth
	NtfLogout
	ReqInfo
	AckInfo
)

//Message portal message
type Message struct {
	Head  Header
	Attrs []Attr
}

//AuthBy generate authenticator
func (msg *Message) AuthBy(secret string) {
	hash := md5.New()
	hash.Write(msg.Bytes())
	hash.Write([]byte(secret))

	msg.Head.Authenticator = hash.Sum(nil)
}

//Bytes marshal message to bytes
func (msg *Message) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, msg.Head.Version)
	binary.Write(buf, binary.BigEndian, msg.Head.Type)
	binary.Write(buf, binary.BigEndian, msg.Head.Pap)
	binary.Write(buf, binary.BigEndian, msg.Head.Rsv)
	binary.Write(buf, binary.BigEndian, msg.Head.SerialNo)
	binary.Write(buf, binary.BigEndian, msg.Head.ReqIdentifier)
	binary.Write(buf, binary.BigEndian, msg.Head.UserIP)
	binary.Write(buf, binary.BigEndian, msg.Head.UserPort)
	binary.Write(buf, binary.BigEndian, msg.Head.ErrCode)
	binary.Write(buf, binary.BigEndian, msg.Head.AttrNum)
	binary.Write(buf, binary.BigEndian, msg.Head.Authenticator)
	for _, v := range msg.Attrs {
		binary.Write(buf, binary.BigEndian, v.Type)
		binary.Write(buf, binary.BigEndian, v.Len+2)
		binary.Write(buf, binary.BigEndian, v.Str)
	}
	return buf.Bytes()
}

//CheckFor check message error
func (msg *Message) CheckFor(req Message, secret string) error {
	if msg.Head.ErrCode == 0 {
		return nil
	}

	des := "未知错误"
	wanted := msg.Head.Authenticator
	msg.Head.Authenticator = req.Head.Authenticator
	msg.AuthBy(secret)
	if bytes.Compare(msg.Head.Authenticator, wanted) != 0 {
		return fmt.Errorf("MD5鉴权错误")
	}
	switch msg.Head.Type {
	case AckChallenge:
		switch msg.Head.ErrCode {
		case 1:
			des = "请求Challenge被拒绝"
		case 2:
			fmt.Println("此链接已建立")
			return nil
		case 3:
			des = "有一个用户正在认证过程中，请稍后再试"
		case 4:
			des = "此用户请求Challenge失败(发生错误)"
		}
	case AckAuth:
		switch msg.Head.ErrCode {
		case 1:
			des = "认证请求被拒绝"
		case 2:
			fmt.Println("此链接已建立")
			return nil
		case 3:
			des = "有一个用户正在认证过程中，请稍后再试"
		case 4:
			des = "此用户请求认证失败(发生错误)"
		}
	}
	return fmt.Errorf("No. %d:%s", msg.Head.ErrCode, des)
}

//Header portal protocal header
type Header struct {
	Version       byte
	Type          byte
	Pap           byte
	Rsv           byte
	SerialNo      uint16
	ReqIdentifier uint16
	UserIP        net.IP
	UserPort      uint16
	ErrCode       byte
	AttrNum       byte
	Authenticator []byte
}

//Attr tlv attribute
type Attr struct {
	Type byte
	Len  byte
	Str  []byte
}

func packHeader(typ byte, userip net.IP, serialNo uint16, reqID uint16) *Header {
	h := new(Header)
	h.Version = curVersion
	h.Type = typ
	h.SerialNo = serialNo
	h.ReqIdentifier = reqID
	h.UserIP = userip.To4()
	h.Authenticator = make([]byte, 16)
	return h
}
