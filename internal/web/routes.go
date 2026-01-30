package web

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"vpp-go-test/internal/vpp"
)

func SetupRoutes(r *gin.Engine, client *vpp.VPPClient /*collector *flow.Collector*/) {
	store := cookie.NewStore([]byte("sarhad_secret_123"))

	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 8, // 8 soat
		HttpOnly: true,
		Secure:   false, // dev: false, prod(https): true
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

	backupHandler := NewBackupHandler(client)

	ipGroupsService := vpp.NewIPGroupsService()
	ipGroupsHandler := NewIPGroupsHandler(ipGroupsService)

	r.GET("/login", auth.LoginGet)
	r.POST("/login", auth.LoginPost)
	r.GET("/logout", auth.Logout)

	protected := r.Group("/")
	protected.Use(AuthMiddleware())
	{
		protected.GET("/", func(c *gin.Context) {
			session := sessions.Default(c)
			c.HTML(200, "dashboard.html", gin.H{
				"title":  "Dashboard",
				"active": "dashboard",
				"user":   session.Get("user_id"),
			})
		})

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
				"title":  "Policer",
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
				"title":  "Traffic Inspection",
				"active": "tls_interception_page",
				"user":   session.Get("user_id"),
			})
		})

		api := protected.Group("/api")
		{
			api.POST("/admin/change-password", auth.ChangePassword)
			api.GET("/logs", logHandler.GetLogs)

			// INTERFACES
			api.GET("/interfaces", iface.ListInterfaces)
			api.POST("/interfaces/state", iface.SetState)
			api.POST("/interfaces/tag", iface.SetTag)
			api.POST("/interfaces/mac", iface.SetMAC)
			api.POST("/interfaces/add-ip", iface.AddIP)
			api.POST("/interfaces/remove-ip", iface.RemoveIP)
			api.POST("/interfaces/dhcp", iface.SetDHCP)

			// VIRTUAL INTERFACES
			api.POST("/interfaces/create-loopback", iface.CreateLoopback)
			api.POST("/interfaces/create-vhost", iface.CreateVhostUser)
			api.POST("/interfaces/delete", iface.DeleteInterface)
			api.POST("/interfaces/create-tap", iface.CreateTap)
			api.POST("/create/vlan", iface.CreateVlan)

			// --- VMXNET3 ---
			api.GET("/interfaces/vmxnet3", iface.ListVmxnet3)
			api.POST("/interfaces/vmxnet3/create", iface.CreateVmxnet3)
			api.POST("/interfaces/vmxnet3/delete", iface.DeleteVmxnet3)

			backup := api.Group("/backup")
			{
				backup.POST("/save", backupHandler.SaveBackup)
				backup.POST("/restore", backupHandler.RestoreBackup)
				backup.GET("/status", backupHandler.GetBackupStatus)
			}

			api.GET("/pci", iface.ScanAvailableInterfaces)
			api.GET("/stats", iface.GetStats)

			// ROUTING
			api.GET("/routes", routing.GetRoutes)
			api.POST("/routes", routing.CreateRoute)
			api.DELETE("/routes", routing.DeleteRoute)

			// ACL
			aclApi := api.Group("/acl")
			{
				aclApi.GET("", aclHandler.ListACLs)
				aclApi.POST("", aclHandler.CreateACL)
				aclApi.PUT("/:index", aclHandler.UpdateACL)
				aclApi.DELETE("/:index", aclHandler.DeleteACL)

				aclApi.POST("/interface/apply", aclHandler.ApplyToInterface)
				aclApi.GET("/interface/all", aclHandler.ListInterfaceMaps)
			}

			api.GET("/mac-acl", aclHandler.ListMacACLs)
			api.POST("/mac-acl", aclHandler.CreateMacACL)
			api.PUT("/mac-acl/:index", aclHandler.UpdateMacACL)
			api.DELETE("/mac-acl/:index", aclHandler.DeleteMacACL)
			api.GET("/mac-acl/interface/all", aclHandler.GetMacInterfaceMaps)
			api.POST("/mac-acl/interface/apply", aclHandler.ApplyMacToInterface)
			api.POST("/mac-acl/interface/unapply", aclHandler.UnbindMacFromInterface)
			api.GET("/acl/interface/full-map", aclHandler.GetFullInterfaceACLMap)

			// NAT
			natApi := api.Group("/nat")
			{
				natApi.GET("/interfaces", natHandler.HandleGetInterfaces)
				natApi.POST("/interface", natHandler.HandleSetInterfaceNAT)
				natApi.GET("/pool", natHandler.HandleGetPool)
				natApi.POST("/pool", natHandler.HandleAddAddressPool)

				natApi.GET("/static", natHandler.HandleGetStaticMappings)
				natApi.POST("/static", natHandler.HandleStaticMapping)

				natApi.POST("/settings/timeouts", natHandler.HandleSetTimeouts)

				natApi.GET("/sessions", natHandler.HandleGetSessions)
				natApi.POST("/sessions/clear", natHandler.HandleClearSessions)
				natApi.POST("/sessions/del", natHandler.HandleDelSpecificSession)

				natApi.POST("/ipfix", natHandler.HandleSetIpfixLogging)
				natApi.GET("/config", natHandler.HandleGetNatConfig)
				natApi.POST("/enable", natHandler.HandleEnableNAT)
			}

			// POLICER
			policerApi := api.Group("/policer")
			{
				policerApi.GET("/policies", policerHandler.HandleListPolicers)
				policerApi.POST("/policy", policerHandler.HandleCreatePolicer)
				policerApi.DELETE("/policy/:index", policerHandler.HandleDeletePolicer)
				policerApi.POST("/bind", policerHandler.HandleBindInterface)
			}

			// FLOW/IPFIX
			flowApi := api.Group("/flow")
			{
				flowApi.GET("/ipfix", ipfixHandler.ShowSettings)
				flowApi.POST("/ipfix", ipfixHandler.SaveSettings)
				flowApi.POST("/ipfix/flush", ipfixHandler.FlushFlows)
			}

			ipfixApi := api.Group("/ipfix")
			{
				ipfixApi.GET("/flowprobe", ipfixHandler.GetFlowprobe)
				ipfixApi.POST("/flowprobe", ipfixHandler.UpdateFlowprobe)
				ipfixApi.POST("/interface", ipfixHandler.ToggleInterface)
				ipfixApi.GET("/interfaces/enabled", ipfixHandler.GetEnabledInterfaces)
			}

			// DHCP
			dhcpApi := api.Group("/dhcp")
			{
				dhcpApi.GET("/proxies", dhcpHandler.HandleGetProxies)
				dhcpApi.POST("/proxy", dhcpHandler.HandleConfigureProxy)
				dhcpApi.POST("/vss", dhcpHandler.HandleSetVSS)
				dhcpApi.GET("/leases", dhcpHandler.HandleGetLeases)

				dhcpApi.GET("/kea-config", dhcpHandler.HandleGetKeaConfig)
				dhcpApi.POST("/kea-config", dhcpHandler.HandleSaveKeaSubnet)
				dhcpApi.DELETE("/kea-subnet/:id", dhcpHandler.HandleDeleteKeaSubnet)
			}

			// ABF
			abfApi := api.Group("/abf")
			{
				abfApi.GET("/policies", abfHandler.HandleGetPolicies)
				abfApi.POST("/policy", abfHandler.HandleCreatePolicy)
				abfApi.POST("/attach", abfHandler.HandleAttachInterface)
				abfApi.GET("/attachments", abfHandler.HandleGetAttachments)
				abfApi.GET("/interfaces", abfHandler.HandleGetInterfacesForABF)
				abfApi.POST("/policies/bulk", abfHandler.HandleCreateMultiplePolicies)
			}

			// IP GROUPS
			ipGroupsApi := api.Group("/ip-groups")
			{
				ipGroupsApi.POST("/upload", ipGroupsHandler.HandleUploadFile)
				ipGroupsApi.GET("/stats", ipGroupsHandler.HandleStats)
				ipGroupsApi.GET("", ipGroupsHandler.HandleGetGroups)
				ipGroupsApi.POST("", ipGroupsHandler.HandleCreateGroup)
				ipGroupsApi.GET("/:id", ipGroupsHandler.HandleGetGroupByID)
				ipGroupsApi.GET("/:id/download", ipGroupsHandler.HandleDownloadGroup)
				ipGroupsApi.PUT("/:id", ipGroupsHandler.HandleUpdateGroup)
				ipGroupsApi.DELETE("/:id", ipGroupsHandler.HandleDeleteGroup)
			}

			// TLS INTERCEPTION
			tlsHandler := NewTLSInterceptionHandler(client)
			tlsApi := api.Group("/tls-interception")
			{
				tlsApi.GET("/status", tlsHandler.GetStatus)
				tlsApi.GET("/simple-status", tlsHandler.GetSimpleStatus)
				// tlsApi.GET("/logs", tlsHandler.GetLogs)

				tlsApi.GET("/config", tlsHandler.GetConfig)
				tlsApi.PUT("/config", tlsHandler.UpdateConfig)

				tlsApi.POST("/enable", tlsHandler.Enable)
				tlsApi.POST("/disable", tlsHandler.Disable)

				tlsApi.GET("/certificates", tlsHandler.GetCertificateInfo)
				tlsApi.POST("/certificates/upload", tlsHandler.UploadCACert)
			}
		}
	}
}
