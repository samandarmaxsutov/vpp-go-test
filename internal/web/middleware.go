package web

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user_id")

		if user == nil {
			if strings.HasPrefix(c.Request.URL.Path, "/api") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Ruxsat yo'q"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		// Read-only user check
		role := session.Get("role")
		if role == "readonly" && c.Request.Method != http.MethodGet {
			// Allow only GET requests for readonly users
			c.JSON(http.StatusForbidden, gin.H{"error": "Read-only user: Configuration changes are not allowed."})
			c.Abort()
			return
		}

		c.Next()
	}
}
