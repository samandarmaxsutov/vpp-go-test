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

// func main() {
// 	// 1. VPP ulanish
// 	client, err := vpp.ConnectVPP("/run/vpp/api.sock", "/dev/shm/vpp/stats.sock")
// 	if err != nil {
// 		log.Fatal("VPP Connect Error:", err)
// 	}
// 	defer client.Close()



// 	client.StartTime = time.Now()
// 	r := gin.Default()

// 	r.Static("/static", "./static")
// 	r.LoadHTMLGlob("templates/**/*.html")

// 	web.SetupRoutes(r, client /*flowColl*/)

// 	log.Println("VPP Management Web server http://localhost:8080 da ishlamoqda")
// 	r.Run(":8000")
// }


func main() {
    // 1. Initial Connect
    client, err := vpp.ConnectVPP("/run/vpp/api.sock", "/dev/shm/vpp/stats.sock")
    if err != nil {
        log.Printf("⚠️ VPP not running on start: %v", err)
        // We don't exit; the watcher below will connect when VPP starts
    }

    // 2. Start the Auto-Reconnection & Restore Watcher
    go func() {
        for {
            if !client.IsConnected() {
                log.Println("🚨 VPP connection lost. Retrying...")
                
                newClient, err := vpp.ConnectVPP("/run/vpp/api.sock", "/dev/shm/vpp/stats.sock")
                if err == nil {
                    log.Println("✅ VPP Reconnected! Waiting for plugins to load...")
                    
                    // Essential: Wait for ACL and other plugins to initialize inside VPP
                    time.Sleep(3 * time.Second)

                    // Update the existing client reference
                    *client = *newClient
                    
                    // 3. TRIGGER AUTO RESTORE
                    log.Println("🔄 Starting Auto-Restore...")
                    if err := client.RestoreConfiguration(); err != nil {
                        log.Printf("❌ Auto-Restore failed: %v", err)
                    } else {
                        log.Println("🎉 Auto-Restore finished successfully.")
                    }
                }
            }
            time.Sleep(5 * time.Second) // Check status every 5 seconds
        }
    }()

    // 4. Start Web Server
    client.StartTime = time.Now()
    r := gin.Default()
    r.Static("/static", "./static")
    r.LoadHTMLGlob("templates/**/*.html")
    web.SetupRoutes(r, client)

    log.Println("VPP Management Web server running on :8000")
    r.Run(":8000")
}