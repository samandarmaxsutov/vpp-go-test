package web

import (
	"fmt"
	"net/http"
	"vpp-go-test/internal/logger"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Global o'zgaruvchi (bazangiz bo'lmagani uchun)
var CurrentAdminPassword = "admin123"

type AuthHandler struct{}

// Login sahifasini ko'rsatish (GET)
func (h *AuthHandler) LoginGet(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Tizimga kirish",
	})
}

// Login qilish jarayoni (POST)
func (h *AuthHandler) LoginPost(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "admin" && password == CurrentAdminPassword {
		session := sessions.Default(c)
		session.Set("user_id", username)
		session.Set("role", "admin")
		session.Save()

		// AUTH turidagi log - Muvaffaqiyatli kirish
		logger.LogAuth(username, c.ClientIP(), "Login", "SUCCESS")

		c.Redirect(http.StatusFound, "/")
	} else if username == "user1" && password == "user1pass" {
		session := sessions.Default(c)
		session.Set("user_id", username)
		session.Set("role", "readonly")
		session.Save()

		logger.LogAuth(username, c.ClientIP(), "Login", "SUCCESS")
		c.Redirect(http.StatusFound, "/")
	} else {
		// AUTH turidagi log - Xato urinish
		logger.LogAuth(username, c.ClientIP(), "Login Attempt", "FAILED")
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "Login yoki parol xato!",
		})
	}
}

// Tizimdan chiqish (Logout)
func (h *AuthHandler) Logout(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user_id")

	// Kim chiqib ketayotganini log qilish
	logger.LogAuth(fmt.Sprintf("%v", user), c.ClientIP(), "Logout", "SUCCESS")

	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

// Parolni o'zgartirish (Bu metod LogHandler yoki AuthHandler ichida bo'lishi mumkin)
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ma'lumotlar to'liq emas"})
		return
	}

	// Check permissions
	session := sessions.Default(c)
	role := session.Get("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Huquq yetarli emas"})
		return
	}

	// 1. Joriy parolni tekshirish
	if input.CurrentPassword != CurrentAdminPassword {
		logger.LogAuth("admin", c.ClientIP(), "Password Change", "WRONG_CURRENT_PASSWORD")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Eski parol noto'g'ri!"})
		return
	}

	// 2. Yangi parolni saqlash
	CurrentAdminPassword = input.NewPassword

	// 3. WEB turidagi log - Parol o'zgartirildi
	logger.LogConfigChange("admin", c.ClientIP(), "UPDATE", "Admin Password", "Password changed successfully")

	c.JSON(http.StatusOK, gin.H{"status": "Parol muvaffaqiyatli o'zgartirildi"})
}
