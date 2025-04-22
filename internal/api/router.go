package api

import (
	"github.com/gin-gonic/gin"
)

// Router sets up the API routes
func SetupRouter(handler *Handler, middleware *Middleware) *gin.Engine {
	router := gin.Default()

	// Public routes
	router.POST("/api/register", handler.HandleUserRegistration)
	router.POST("/api/login", handler.HandleUserLogin)
	router.GET("/api/confirm-permission/:token", handler.HandleConfirmPermission)

	// Protected routes
	authGroup := router.Group("/api")
	authGroup.Use(middleware.AuthRequired())
	{
		authGroup.POST("/mailboxes", handler.HandleCreateMailbox)
		authGroup.GET("/mailboxes", handler.HandleListMailboxes)
		authGroup.GET("/emails/:mailboxId", handler.HandleListEmails)
		authGroup.GET("/emails/:mailboxId/:emailId", handler.HandleGetEmail)
		authGroup.DELETE("/emails/:mailboxId/:emailId", handler.HandleDeleteEmail)
		authGroup.POST("/request-permission", handler.HandleRequestPermission)
		authGroup.POST("/send-external", handler.HandleSendExternalEmail)
		authGroup.POST("/send-with-attachment", handler.HandleSendEmailWithAttachment)
		authGroup.GET("/emails/:mailboxId/:emailId/attachments", handler.HandleGetEmailAttachments)
		authGroup.GET("/emails/:mailboxId/:emailId/attachments/:attachmentId", handler.HandleDownloadAttachment)

		// Admin routes
		adminGroup := authGroup.Group("/admin")
		adminGroup.Use(middleware.AdminRequired())
		{
			adminGroup.GET("/users", handler.HandleListUsers)
			adminGroup.POST("/trusted-domains", handler.HandleAddTrustedDomain)
			adminGroup.DELETE("/trusted-domains/:domain", handler.HandleRemoveTrustedDomain)
		}
	}

	return router
}
