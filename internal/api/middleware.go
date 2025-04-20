package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/yourusername/emailserver/internal/app"
)

/* ------------------------------------------------------------------
   Auth middleware — unchanged
-------------------------------------------------------------------*/

func authMiddleware(a *app.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		parts := strings.SplitN(h, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header required"})
			return
		}

		token, err := jwt.Parse(parts[1], func(t *jwt.Token) (interface{}, error) {
			return []byte(a.GetConfig().JWTSecret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("userID", claims["user_id"].(string))
		c.Set("isAdmin", claims["is_admin"].(bool))
		c.Next()
	}
}

/* ------------------------------------------------------------------
   Admin‑only middleware — NEW
-------------------------------------------------------------------*/

func adminMiddleware(a *app.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, ok := c.Get("isAdmin")
		if !ok || !isAdmin.(bool) {
			c.AbortWithStatusJSON(403, gin.H{"error": "Admin access required"})
			return
		}
		c.Next()
	}
}
