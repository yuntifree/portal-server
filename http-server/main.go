package main

import (
	"github.com/gin-gonic/gin"
	jsonp "github.com/tomwei7/gin-jsonp"
)

func main() {
	r := gin.Default()
	r.Use(jsonp.JsonP())
	r.GET("/portal", portalHandler)
	r.GET("/check_login", checkLoginHandler)
	r.GET("/get_check_code", getCodeHandler)
	r.GET("/portal_login", portalLoginHandler)
	r.GET("/logout", logoutHandler)
	r.Static("/static/", "/home/darren/html")
	r.Run(":8080")
}
