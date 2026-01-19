package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"time"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/web"
)

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

				// Try to connect
				newClient, err := vpp.ConnectVPP("/run/vpp/api.sock", "/dev/shm/vpp/stats.sock")
				if err == nil {
					// Update the core connection pointers
					client.Conn = newClient.Conn
					client.Stats = newClient.Stats

					// CRITICAL: Refresh all sub-managers so they don't have broken pipes
					client.RefreshManagers()

					log.Println("✅ VPP Reconnected and Managers Refreshed!")

					time.Sleep(3 * time.Second)
					if err := client.RestoreConfiguration(); err != nil {
						log.Printf("❌ Auto-Restore failed: %v", err)
					}
				}
			}
			time.Sleep(5 * time.Second)
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
