package main

import (
	"log"
	"time"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/web"

	"github.com/gin-gonic/gin"
)

func main() {
	client, err := vpp.ConnectVPP("/run/sarhad-guard/api.sock", "/dev/shm/sarhad-guard/stats.sock")
	if err != nil {
		log.Printf("Sarhad-FW not running on start: %v", err)

	}

	go func() {
		for {
			if !client.IsConnected() {
				log.Println(" Sarhad-FW  connection lost. Retrying...")

				newClient, err := vpp.ConnectVPP("/run/sarhad-guard/api.sock", "/dev/shm/sarhad-guard/stats.sock")
				if err == nil {
					client.Conn = newClient.Conn
					client.Stats = newClient.Stats

					client.RefreshManagers()

					log.Println("Sarhad-FW Reconnected and Managers Refreshed!")

					time.Sleep(3 * time.Second)
					if err := client.RestoreConfiguration(); err != nil {
						log.Printf("Auto-Restore failed: %v", err)
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
	}()

	client.StartTime = time.Now()
	r := gin.Default()

	// Add cache control middleware for development
	r.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	})

	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/**/*.html")
	web.SetupRoutes(r, client)

	log.Println("Sarhad-FW Management Web server running on :8000")
	r.Run(":8000")
}
