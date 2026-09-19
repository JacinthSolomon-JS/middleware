package api

import (
	"fmt"
	"middleware/pkg/storage"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Server struct {
	db     *storage.Database
	hub    *WSHub
	router *gin.Engine
	addr   string
}

func (s *Server) Start() error {
	fmt.Printf("[API] Dashboard Server listening on http://%s\n", s.addr)
	return s.router.Run(s.addr)
}

func NewServer(addr string, db *storage.Database, hub *WSHub) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	s := &Server{
		db:     db,
		hub:    hub,
		router: router,
		addr:   addr,
	}

	s.setupRoutes()
	return s
}

func (s *Server) handleSummary(c *gin.Context) {
	summary, err := s.db.GetSummary()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, summary)
}

func (s *Server) setupRoutes() {
	s.router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Next()
	})

	api := s.router.Group("/api/v1")
	{
		api.GET("/summary", s.handleSummary)
		api.GET("/summary/:id", s.handleSummary)
		api.GET("/ws", func(c *gin.Context) {
			s.hub.HandleWS(c.Writer, c.Request)
		})
	}
}
