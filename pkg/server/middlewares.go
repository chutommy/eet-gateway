package server

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (h *handler) loggingMiddleware(c *gin.Context) {
	start := time.Now()
	c.Next()
	log.Info().
		Timestamp().
		Str("client", c.ClientIP()).
		Str("method", c.Request.Method).
		Str("uri", c.Request.URL.RequestURI()).
		Int("status", c.Writer.Status()).
		TimeDiff("latency", time.Now(), start).
		Send()
}
