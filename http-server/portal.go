package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/micro/go-micro/client"
	verify "github.com/yuntifree/portal-server/proto/verify"
)

const (
	portalDir  = "/static/login201712041340"
	verifyName = "go.micro.srv.verify"
)

func portalHandler(c *gin.Context) {
	var postfix string
	pos := strings.Index(c.Request.RequestURI, "?")
	if pos != -1 {
		postfix = c.Request.RequestURI[pos:]
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusMovedPermanently, portalDir+postfix)
}

func checkLoginHandler(c *gin.Context) {
	var req verify.CheckRequest
	req.Wlanusermac = c.Query("wlanusermac")
	req.Wlanacname = c.Query("wlanacname")
	req.Wlanapmac = c.Query("wlanapmac")
	cl := verify.NewVerifyClient(verifyName, client.DefaultClient)
	rsp, err := cl.CheckLogin(context.Background(), &req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"errno": 1, "desc": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"errno": 0, "data": map[string]interface{}{
		"autologin": rsp.Autologin, "img": rsp.Img, "wxappid": rsp.Wxappid,
		"wxsecret": rsp.Wxsecret, "wxshopid": rsp.Wxshopid, "wxauthurl": rsp.Wxauthurl,
		"taobao": rsp.Taobao, "logintype": rsp.Logintype, "dst": rsp.Dst,
		"cover": rsp.Cover}})
}

func getCodeHandler(c *gin.Context) {
	var req verify.CodeRequest
	req.Phone = c.Query("phone")
	req.Wlanacname = c.Query("wlanacname")
	req.Wlanapmac = c.Query("wlanapmac")
	cl := verify.NewVerifyClient(verifyName, client.DefaultClient)
	_, err := cl.GetCheckCode(context.Background(), &req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"errno": 1, "desc": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"errno": 0})
}
func portalLoginHandler(c *gin.Context) {
	var req verify.PortalLoginRequest
	req.Phone = c.Query("phone")
	req.Code = c.Query("code")
	req.Wlanacname = c.Query("wlanacname")
	req.Wlanuserip = c.Query("wlanuserip")
	req.Wlanacip = c.Query("wlanacip")
	req.Wlanapmac = c.Query("wlanapmac")
	req.Wlanusermac = c.Query("wlanusermac")
	cl := verify.NewVerifyClient(verifyName, client.DefaultClient)
	rsp, err := cl.PortalLogin(context.Background(), &req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"errno": 1, "desc": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"errno": 0, "data": map[string]interface{}{
		"uid": rsp.Uid, "token": rsp.Token, "portaldir": rsp.Portaldir,
		"portaltype": rsp.Portaltype, "adtype": rsp.Adtype,
		"cover": rsp.Cover, "dst": rsp.Dst}})
}
