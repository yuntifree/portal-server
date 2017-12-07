package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
	micro "github.com/micro/go-micro"
	"github.com/yuntifree/components/dbutil"
	"github.com/yuntifree/components/sms"
	"github.com/yuntifree/portal-server/accounts"
	"github.com/yuntifree/portal-server/conn"
	verify "github.com/yuntifree/portal-server/proto/verify"
	context "golang.org/x/net/context"
)

const (
	adImg       = "http://192.168.18.252:8080/static/img/115cebf5-2ad3-458f-bc2c-48c667eacd52.png"
	wxAppid     = "wx0898ab51f688ee64"
	wxSecret    = "bf430af449b70efc04f11964bc5968a3"
	wxShopid    = "3535655"
	wxAuthURL   = "http://wx.yunxingzh.com/auth"
	portalDir   = "http://api.yunxingzh.com/portal0406201704201946/index0406.html"
	tstUID      = 137
	tstToken    = "6ba9ac5a422d4473b337d57376dd3488"
	tstUsername = "test"
	tstPasswd   = "test"
)

var db *sql.DB

//Server server  implement
type Server struct{}

//GetCheckCode get check code
func (s *Server) GetCheckCode(ctx context.Context, req *verify.CodeRequest,
	rsp *verify.CodeResponse) error {
	var code int

	err := db.QueryRow(`SELECT code FROM phone_code WHERE phone = ?
			AND used = 0 AND etime > NOW() AND
			timestampdiff(second, stime, now()) < 300 ORDER BY id DESC LIMIT 1`,

		req.Phone).Scan(&code)

	if err != nil {
		code = genCode()
		_, err := db.Exec(`INSERT INTO phone_code(phone, code, ctime,
		stime, etime) VALUES (?, ?, NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 5 MINUTE))`,
			req.Phone, code)

		if err != nil {

			log.Printf("insert into phone_code failed:%s %v", req.Phone, err)

			return err

		}

		ret := sendSMS(req.Phone, code)

		if ret != 0 {

			log.Printf("send sms code failed:%s %d", req.Phone, ret)

			return fmt.Errorf("send sms failed:%d", ret)

		}

		return nil

	}

	if code > 0 {

		ret := sendSMS(req.Phone, code)

		if ret != 0 {
			log.Printf("send sms failed:%s %d", req.Phone, ret)
			return fmt.Errorf("send sms failed:%d", ret)
		}

	}

	return nil
}
func sendSMS(phone string, code int) int {
	yp := sms.Yunpian{Apikey: accounts.YPSMSApiKey,
		TplID: accounts.YPSMSTplID}
	return yp.Send(phone, code)
}

func genCode() int {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return int(r.Int31n(1e6))

}

//CheckLogin check login
func (s *Server) CheckLogin(ctx context.Context, req *verify.CheckRequest,
	rsp *verify.CheckResponse) error {
	rsp.Autologin = isAutoMac(db, req.Wlanusermac, req.Wlanapmac)
	rsp.Img = adImg
	rsp.Wxappid = wxAppid
	rsp.Wxsecret = wxSecret
	rsp.Wxshopid = wxShopid
	rsp.Wxauthurl = wxAuthURL
	rsp.Taobao = 0
	rsp.Logintype = 1
	return nil
}

func isAutoMac(db *sql.DB, usermac, apmac string) int64 {
	var phone string
	err := db.QueryRow(`SELECT phone FROM user_mac WHERE mac = ?`, usermac).
		Scan(&phone)
	if err != nil || phone == "" {
		return 0
	}

	return 1
}

func challenge(userip, username, passwd string) error {
	ip := net.ParseIP(accounts.Acip)
	c := conn.Conn{Acip: ip,
		Acport:   accounts.Acport,
		ShareKey: accounts.ShareKey,
		Timeout:  accounts.Timeout}
	uip := net.ParseIP(userip)
	id, cha, err := c.Challenge(uip)
	if err != nil {
		return err
	}
	log.Printf("id:%d cha:%+v", id, cha)
	err = c.Auth(uip, []byte(username), []byte(passwd), cha, id)
	return err
}

//PortalLogin portal login
func (s *Server) PortalLogin(ctx context.Context, req *verify.PortalLoginRequest,
	rsp *verify.LoginResponse) error {
	if !checkPhoneCode(db, req.Phone, req.Code) {
		return errors.New("illegal phone code")
	}
	if err := challenge(req.Wlanuserip, tstUsername, tstPasswd); err != nil {
		return errors.New("challenge failed:" + err.Error())
	}
	if err := createUser(db, req.Phone, req.Wlanusermac); err != nil {
		return errors.New("create user failed:" + err.Error())
	}
	addOnlineRecord(db, req.Phone, req.Wlanacname, req.Wlanacip, req.Wlanusermac,
		req.Wlanuserip, req.Wlanapmac)
	rsp.Uid = tstUID
	rsp.Token = tstToken
	rsp.Portaldir = portalDir
	rsp.Portaltype = 1
	return nil
}

//OneClickLogin one click login
func (s *Server) OneClickLogin(ctx context.Context, req *verify.OneClickRequest,
	rsp *verify.LoginResponse) error {
	var phone string
	err := db.QueryRow(`SELECT phone FROM user_mac WHERE mac = ?`, req.Wlanusermac).
		Scan(&phone)
	if err != nil {
		log.Printf("OneClickLogin query phone failed:%v", err)
		return err
	}
	if err := challenge(req.Wlanuserip, tstUsername, tstPasswd); err != nil {
		return errors.New("challenge failed:" + err.Error())
	}
	addOnlineRecord(db, phone, req.Wlanacname, req.Wlanacip, req.Wlanusermac,
		req.Wlanuserip, req.Wlanapmac)
	rsp.Uid = tstUID
	rsp.Token = tstToken
	rsp.Portaldir = portalDir
	rsp.Portaltype = 1
	return nil
}

func genOnlineTable() string {
	now := time.Now()
	return fmt.Sprintf("online_record_%04d%02d", now.Year(), now.Month())
}

func createOnlineTable(db *sql.DB, table string) error {
	_, err := db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s LIKE 
	online_record`, table))
	if err != nil {
		log.Printf("createOnlineTable %s failed:%v", table, err)
		return err
	}
	return nil

}

func addOnlineRecord(db *sql.DB, phone, acname, acip, usermac, userip, apmac string) {
	table := genOnlineTable()
	err := createOnlineTable(db, table)
	if err != nil {
		log.Printf("addOnlineRecord online record failed:%s %v", phone, err)
		return
	}

	query := fmt.Sprintf(`INSERT INTO %s(phone, acname, acip, usermac, userip, 
	apmac, ctime) VALUES (?, ?, ?, ?, ?, ?, NOW())`, table)
	_, err = db.Exec(query, phone, acname, acip, usermac, userip, apmac)
	if err != nil {
		log.Printf("addOnlineRecord online record failed:%s %v", phone, err)
	}

	_, err = db.Exec(`INSERT IGNORE INTO online_users(userip, username, usermac, acname,
	ctime) VALUES (?, ?, ?, ?, NOW())`, userip, phone, usermac, acname)
	if err != nil {
		log.Printf("addOnlineRecord online_users record failed:%v", err)
	}
}

func createUser(db *sql.DB, phone, usermac string) error {
	_, err := db.Exec(`INSERT INTO user_mac(mac, phone, ctime) VALUES (?, ?, 
	NOW()) ON DUPLICATE KEY UPDATE phone = ?`, usermac, phone, phone)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT IGNORE INTO users(username, phone, ctime) VALUES
		(?,?, NOW())`, phone, phone)
	if err != nil {
		return err
	}
	return nil
}

func checkPhoneCode(db *sql.DB, phone, code string) bool {
	var c int
	err := db.QueryRow(`SELECT code FROM phone_code WHERE phone = ? AND
	used = 0 AND etime > NOW() ORDER BY id DESC LIMIT 1`, phone).Scan(&c)
	if err != nil {
		return false
	}
	e := fmt.Sprintf("%06d", c)
	if code == e {
		return true
	}
	return false
}

//Logout logout for ip
func (s *Server) Logout(ctx context.Context, req *verify.LogoutRequest,
	rsp *verify.LogoutResponse) error {
	ip := net.ParseIP(accounts.Acip)
	c := conn.Conn{Acip: ip,
		Acport:   accounts.Acport,
		ShareKey: accounts.ShareKey,
		Timeout:  accounts.Timeout}
	uip := net.ParseIP(req.Ip)
	err := c.Logout(uip)
	if err != nil {
		log.Printf("logout failed:%+v", err)
		return err
	}
	return nil
}

func main() {
	var err error
	db, err = dbutil.NewDB(accounts.DbDsn)
	if err != nil {
		log.Fatal(err)
	}

	service := micro.NewService(
		micro.Name("go.micro.srv.verify"),
		micro.RegisterTTL(30*time.Second),
		micro.RegisterInterval(10*time.Second),
	)

	service.Init()
	verify.RegisterVerifyHandler(service.Server(), new(Server))
	if err := service.Run(); err != nil {
		log.Fatal(err)
	}
}
