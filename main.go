package main

import (
	// "encoding/binary"
	// "fmt"
	"github.com/gin-gonic/gin"
	"log"
	// "net"
	// "context"
	"time"
	"vpp-go-test/internal/vpp"
	// "vpp-go-test/internal/flow"
	"vpp-go-test/internal/web"
)


func main() {
	// 1. VPP ulanish
	client, err := vpp.ConnectVPP("/run/vpp/api.sock", "/dev/shm/vpp/stats.sock")
	if err != nil {
		log.Fatal("VPP Connect Error:", err)
	}
	defer client.Close()


	// // 2. Flow Collector-ni yaratish
	// flowColl := flow.NewCollector(4739, 1000)
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	// // 3. Collectorni alohida goroutine-da ishga tushirish
	// go func() {
	// 	log.Println("IPFIX Collector started on port 4739")
	// 	if err := flowColl.Start(ctx); err != nil {
	// 		log.Printf("Collector error: %v", err)
	// 	}
	// }()

	client.StartTime = time.Now()
	r := gin.Default()


	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/**/*.html")


	web.SetupRoutes(r, client, /*flowColl*/)

	log.Println("VPP Management Web server http://localhost:8080 da ishlamoqda")
	r.Run(":8000")
}
