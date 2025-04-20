package api

import (
	"github.com/gin-gonic/gin"

	"github.com/yourusername/emailserver/internal/app"
)

/*
SetupRouter wires every HTTP endpoint exactly as in the
original monolithic file, only using thin closure wrappers
so each handler receives the running *app.App instance.
*/
func SetupRouter(a *app.App) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	/* ---------- public endpoints ---------- */
	r.POST("/api/register", func(c *gin.Context) { handleUserRegistration(a, c) })
	r.POST("/api/login", func(c *gin.Context) { handleUserLogin(a, c) })
	r.GET("/api/confirm-permission/:token",
		func(c *gin.Context) { handleConfirmPermission(a, c) })

	/* ---------- protected endpoints ---------- */
	api := r.Group("/api")
	api.Use(authMiddleware(a))
	{
		api.POST("/mailboxes", func(c *gin.Context) { handleCreateMailbox(a, c) })
		api.GET("/mailboxes", func(c *gin.Context) { handleListMailboxes(a, c) })
		api.GET("/emails/:mailboxId",
			func(c *gin.Context) { handleListEmails(a, c) })
		api.GET("/emails/:mailboxId/:emailId",
			func(c *gin.Context) { handleGetEmail(a, c) })
		api.DELETE("/emails/:mailboxId/:emailId",
			func(c *gin.Context) { handleDeleteEmail(a, c) })
		api.POST("/request-permission",
			func(c *gin.Context) { handleRequestPermission(a, c) })
		api.POST("/send", func(c *gin.Context) { handleSendEmail(a, c) })

		/* ----- admin sub‑group ----- */
		admin := api.Group("/admin")
		admin.Use(adminMiddleware(a))
		{
			admin.GET("/users", func(c *gin.Context) { handleListUsers(a, c) })
			admin.POST("/trusted-domains",
				func(c *gin.Context) { handleAddTrustedDomain(a, c) })
			admin.DELETE("/trusted-domains/:domain",
				func(c *gin.Context) { handleRemoveTrustedDomain(a, c) })
		}
	}

	return r
}
