package web

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	// "vpp-go-test/internal/flow"
	"vpp-go-test/internal/vpp"
)

func SetupRoutes(r *gin.Engine, client *vpp.VPPClient /*collector *flow.Collector*/) {
	store := cookie.NewStore([]byte("sarhad_secret_123"))

	// Sessiya parametrlarini sozlash
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 8, // 8 soat
		HttpOnly: true,
		Secure:   false, // Ishlab chiqish uchun false, productionda true qilish kerak -> https uchun
		SameSite: http.SameSiteLaxMode,
	})

	r.Use(sessions.Sessions("sarhad_session", store))

	auth := &AuthHandler{}
	iface := &InterfaceHandler{VPP: client}
	routing := &RoutingHandler{VPP: client}
	aclHandler := &ACLHandler{VPP: client}
	natHandler := &NatHandler{VPP: client}
	policerHandler := &PolicerHandler{VPP: client}
	dhcpHandler := &DhcpHandler{VPP: client}
	abfHandler := &AbfHandler{VPP: client}
	logHandler := &LogHandler{}
	ipfixHandler := &IpfixHandler{VPP: client}
	// === BACKUP & RESTORE ENDPOINTS ===
	backupHandler := NewBackupHandler(client)
	// === IP GROUPS ENDPOINTS ===
	ipGroupsService := vpp.NewIPGroupsService()
	ipGroupsHandler := NewIPGroupsHandler(ipGroupsService)

	r.GET("/login", auth.LoginGet)
	r.POST("/login", auth.LoginPost)
	r.GET("/logout", auth.Logout)

	protected := r.Group("/")
	protected.Use(AuthMiddleware())
	{
		// Dashboard sahifasi
		protected.GET("/", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "dashboard.html", gin.H{
				"title":  "Dashboard",
				"active": "dashboard",
				"user":   session.Get("user_id"),
			})
		})

		// Interfaces sahifasi
		protected.GET("/interfaces", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "interfaces.html", gin.H{
				"title":  "Network Interfaces",
				"active": "interfaces",
				"user":   session.Get("user_id"),
			})
		})

		protected.GET("/routes", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "routing.html", gin.H{
				"title":  "Routes",
				"active": "routing",
				"user":   session.Get("user_id"),
			})
		})

		protected.GET("/nat", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "nat_page_manager.html", gin.H{
				"title":  "NAT44",
				"active": "nat_page_manager",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/dhcp-server", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "dhcp_server.html", gin.H{
				"title":  "DHCP Server",
				"active": "dhcp",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/policer", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "policer_page_manager.html", gin.H{
				"title":  "Policer ",
				"active": "policer_page_manager",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/acl", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "acl_page_manager.html", gin.H{
				"title":  "Firewall ACL",
				"active": "acl_page_manager",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/abf", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "access_based_fwd.html", gin.H{
				"title":  "Access Based Forwarding",
				"active": "abf_page",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/flow-monitoring", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "flow_page_manager.html", gin.H{
				"title":  "Flow Monitoring",
				"active": "flow_page_manager",
				"user":   session.Get("user_id"),
			})
		})

		protected.GET("/ip-groups", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "ip_groups.html", gin.H{
				"title":  "IP Groups",
				"active": "ip_groups",
				"user":   session.Get("user_id"),
			})
		})

		protected.GET("/time", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "time.html", gin.H{
				"title":  "Time Settings",
				"active": "time_manager",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/logs", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "logs.html", gin.H{
				"title":  "Logs",
				"active": "logs",
				"user":   session.Get("user_id"),
			})
		})
		protected.GET("/tls-interception", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "tls_interception.html", gin.H{
				"title":  "TLS Interception",
				"active": "tls_interception_page",
				"user":   session.Get("user_id"),
			})
		})

		api := protected.Group("/api")
		{
			api.POST("/admin/change-password", auth.ChangePassword)
			api.GET("/logs", logHandler.GetLogs) // Loglarni olish uchun endpoint
			// INTERFACES
			api.GET("/interfaces", iface.ListInterfaces)
			api.POST("/interfaces/state", iface.SetState)
			api.POST("/interfaces/tag", iface.SetTag) // Yangi: Nom berish
			api.POST("/interfaces/mac", iface.SetMAC) // Yangi: MAC o'zgartirish
			api.POST("/interfaces/add-ip", iface.AddIP)
			api.POST("/interfaces/remove-ip", iface.RemoveIP)
			api.POST("/interfaces/dhcp", iface.SetDHCP)

			// VIRTUAL INTERFACES
			api.POST("/interfaces/create-loopback", iface.CreateLoopback)
			api.POST("/interfaces/create-vhost", iface.CreateVhostUser) // Yangi: Vhost yaratish
			api.POST("/interfaces/delete", iface.DeleteInterface)
			api.POST("/interfaces/create-tap", iface.CreateTap)
			api.POST("/create/vlan", iface.CreateVlan)

			// --- VMXNET3 SPECIFIC ---
			api.GET("/interfaces/vmxnet3", iface.ListVmxnet3)           // Ro'yxatni olish
			api.POST("/interfaces/vmxnet3/create", iface.CreateVmxnet3) // Yaratish
			api.POST("/interfaces/vmxnet3/delete", iface.DeleteVmxnet3) // O'chirish

			backup := api.Group("/backup")
			{
				backup.POST("/save", backupHandler.SaveBackup)       // Manual save
				backup.POST("/restore", backupHandler.RestoreBackup) // Manual restore
				backup.GET("/status", backupHandler.GetBackupStatus) // Check if backup exists
			}
			api.GET("/pci", iface.ScanAvailableInterfaces) // PCI qurilmalarni skanerlash

			api.GET("/stats", iface.GetStats)
			api.GET("/routes", routing.GetRoutes) // To'g'irlandi
			api.POST("/routes", routing.CreateRoute)
			api.DELETE("/routes", routing.DeleteRoute)

			// ACL endpoints
			aclApi := api.Group("/acl")
			{
				aclApi.GET("", aclHandler.ListACLs)            // GET /api/acl
				aclApi.POST("", aclHandler.CreateACL)          // POST /api/acl
				aclApi.PUT("/:index", aclHandler.UpdateACL)    // PUT /api/acl/:index  <-- MANA SHU YERDA XATO EDI
				aclApi.DELETE("/:index", aclHandler.DeleteACL) // DELETE /api/acl/:index

				// Interface bog'lamalari
				aclApi.POST("/interface/apply", aclHandler.ApplyToInterface) // POST /api/acl/interface/apply
				aclApi.GET("/interface/all", aclHandler.ListInterfaceMaps)   // GET /api/acl/interface/all

			}

			api.GET("/mac-acl", aclHandler.ListMacACLs)
			api.POST("/mac-acl", aclHandler.CreateMacACL)
			api.PUT("/mac-acl/:index", aclHandler.UpdateMacACL)
			api.DELETE("/mac-acl/:index", aclHandler.DeleteMacACL)
			// MAC ACL Interface Assignment endpoints
			api.GET("/mac-acl/interface/all", aclHandler.GetMacInterfaceMaps)         // Barcha bog'lamalarni olish
			api.POST("/mac-acl/interface/apply", aclHandler.ApplyMacToInterface)      // Bog'lash (Bind)
			api.POST("/mac-acl/interface/unapply", aclHandler.UnbindMacFromInterface) // Uzish (Unbind)

			// Birlashtirilgan to'liq xarita (Ixtiyoriy, frontenddagi ikkala jadvalni bitta so'rovda yangilash uchun)
			api.GET("/acl/interface/full-map", aclHandler.GetFullInterfaceACLMap)

			// --- NAT44 API endpoints ---
			natApi := api.Group("/nat")
			{
				// Infrastructure (Tab 1)
				natApi.GET("/interfaces", natHandler.HandleGetInterfaces) // NAT statusi bor interfeyslar
				natApi.POST("/interface", natHandler.HandleSetInterfaceNAT)
				natApi.GET("/pool", natHandler.HandleGetPool) // Mavjud IP hovuzi
				natApi.POST("/pool", natHandler.HandleAddAddressPool)

				// Inbound/Static Mapping (Tab 2)
				natApi.GET("/static", natHandler.HandleGetStaticMappings)
				natApi.POST("/static", natHandler.HandleStaticMapping)
				// natApi.DELETE("/static", natHandler.HandleDeleteStaticMapping) // Kerak bo'lsa

				// Global Settings (Tab 3)
				natApi.POST("/settings/timeouts", natHandler.HandleSetTimeouts)

				// Session Management (Tab 4)
				natApi.GET("/sessions", natHandler.HandleGetSessions)
				// 404 ni tuzatish: DELETE o'rniga POST ishlatamiz (frontendga moslash uchun)
				natApi.POST("/sessions/clear", natHandler.HandleClearSessions)
				// Ma'lum bir sessiyani uzish uchun (ixtiyoriy)
				natApi.POST("/sessions/del", natHandler.HandleDelSpecificSession)

				natApi.POST("/ipfix", natHandler.HandleSetIpfixLogging)
				natApi.GET("/config", natHandler.HandleGetNatConfig)
				natApi.POST("/enable", natHandler.HandleEnableNAT)
			}

			policerApi := api.Group("/policer")
			{
				policerApi.GET("/policies", policerHandler.HandleListPolicers)          // Ro'yxatni olish
				policerApi.POST("/policy", policerHandler.HandleCreatePolicer)          // Yaratish
				policerApi.DELETE("/policy/:index", policerHandler.HandleDeletePolicer) // Indeks bo'yicha o'chirish
				policerApi.POST("/bind", policerHandler.HandleBindInterface)            // Interfeysga bog'lash
			}
			// ---------------- FLOW / IPFIX ----------------

			flowApi := api.Group("/flow")
			{
				// IPFIX Exporter
				flowApi.GET("/ipfix", ipfixHandler.ShowSettings)
				flowApi.POST("/ipfix", ipfixHandler.SaveSettings)
				flowApi.POST("/ipfix/flush", ipfixHandler.FlushFlows)

				// Live flows from collector
				// flowApi.GET("/live", func(c *gin.Context) {
				// 	flows := collector.GetLatest(50)
				// 	c.JSON(http.StatusOK, flows)
				// })
			}

			// ---------------- FLOWPROBE ----------------

			ipfixApi := api.Group("/ipfix")
			{
				// Flowprobe global params
				ipfixApi.GET("/flowprobe", ipfixHandler.GetFlowprobe)
				ipfixApi.POST("/flowprobe", ipfixHandler.UpdateFlowprobe)

				// Interface enable/disable
				ipfixApi.POST("/interface", ipfixHandler.ToggleInterface)
				ipfixApi.GET("/interfaces/enabled", ipfixHandler.GetEnabledInterfaces)
			}

			dhcpApi := api.Group("/dhcp")
			{
				dhcpApi.GET("/proxies", dhcpHandler.HandleGetProxies)
				dhcpApi.POST("/proxy", dhcpHandler.HandleConfigureProxy)
				dhcpApi.POST("/vss", dhcpHandler.HandleSetVSS)
				dhcpApi.GET("/leases", dhcpHandler.HandleGetLeases)

				dhcpApi.GET("/kea-config", dhcpHandler.HandleGetKeaConfig)   // GET
				dhcpApi.POST("/kea-config", dhcpHandler.HandleSaveKeaSubnet) // ADD/UPDATE (Append ishlaydi)
				dhcpApi.DELETE("/kea-subnet/:id", dhcpHandler.HandleDeleteKeaSubnet)
			}

			abfApi := api.Group("/abf")
			{
				abfApi.GET("/policies", abfHandler.HandleGetPolicies)
				abfApi.POST("/policy", abfHandler.HandleCreatePolicy)
				abfApi.POST("/attach", abfHandler.HandleAttachInterface)
				abfApi.GET("/attachments", abfHandler.HandleGetAttachments)
				abfApi.GET("/interfaces", abfHandler.HandleGetInterfacesForABF)        // Enriched interface list
				abfApi.POST("/policies/bulk", abfHandler.HandleCreateMultiplePolicies) // Bulk create
			}

			// --- IP GROUPS API endpoints ---
			ipGroupsApi := api.Group("/ip-groups")
			{
				// Specific routes MUST come before /:id routes in Gin
				ipGroupsApi.POST("/upload", ipGroupsHandler.HandleUploadFile) // POST upload file
				ipGroupsApi.GET("/stats", ipGroupsHandler.HandleStats)        // GET statistics
				// Generic routes
				ipGroupsApi.GET("", ipGroupsHandler.HandleGetGroups)    // GET all groups
				ipGroupsApi.POST("", ipGroupsHandler.HandleCreateGroup) // POST create group
				// ID-based routes
				ipGroupsApi.GET("/:id", ipGroupsHandler.HandleGetGroupByID)           // GET single group
				ipGroupsApi.GET("/:id/download", ipGroupsHandler.HandleDownloadGroup) // GET download group
				ipGroupsApi.PUT("/:id", ipGroupsHandler.HandleUpdateGroup)            // PUT update group
				ipGroupsApi.DELETE("/:id", ipGroupsHandler.HandleDeleteGroup)         // DELETE group
			}

			// --- TLS INTERCEPTION API endpoints ---
			tlsHandler := NewTLSInterceptionHandler(client)
			tlsApi := api.Group("/tls-interception")
			{
				tlsApi.GET("/status", tlsHandler.GetStatus)                      // GET full status
				tlsApi.GET("/simple-status", tlsHandler.GetSimpleStatus)         // GET user-friendly status
				tlsApi.GET("/logs", tlsHandler.GetLogs)                          // GET inspection logs
				tlsApi.GET("/config", tlsHandler.GetConfig)                      // GET current config
				tlsApi.PUT("/config", tlsHandler.UpdateConfig)                   // PUT update config
				tlsApi.POST("/enable", tlsHandler.Enable)                        // POST enable interception
				tlsApi.POST("/disable", tlsHandler.Disable)                      // POST disable interception
				tlsApi.GET("/scripts", tlsHandler.GetAllScripts)                 // GET all scripts
				tlsApi.GET("/scripts/vpp", tlsHandler.GetVPPScript)              // GET VPP script
				tlsApi.GET("/scripts/kernel", tlsHandler.GetKernelScript)        // GET kernel script
				tlsApi.GET("/scripts/mitmproxy", tlsHandler.GetMitmproxyCommand) // GET mitmproxy cmd
				tlsApi.POST("/scripts/save", tlsHandler.SaveScripts)             // POST save scripts to disk
			}
		}
	}
}
