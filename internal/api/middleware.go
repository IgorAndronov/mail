package api

import (
	"github.com/gin-gonic/gin"
	"github.com/yourusername/emailserver/internal/auth"
	"strings"
)

// Middleware provides API middleware functions
type Middleware struct {
	authService *auth.Service
}

// NewMiddleware creates a new middleware instance
func NewMiddleware(authService *auth.Service) *Middleware {
	return &Middleware{
		authService: authService,
	}
}

// AuthRequired ensures the request has a valid JWT token
func (m *Middleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from Bearer schema
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(401, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		// Verify token
		claims, err := m.authService.VerifyToken(tokenParts[1])
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set user info in context
		userID, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Set("isAdmin", claims["is_admin"].(bool))
		c.Next()
	}
}

// AdminRequired ensures the user is an admin
func (m *Middleware) AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("isAdmin")
		if !exists || !isAdmin.(bool) {
			c.JSON(403, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
