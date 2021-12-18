package httphandler

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func loggingMiddleware(c *gin.Context) {
	start := time.Now()

	c.Next()

	log.Info().
		Str("entity", "HTTP Handler").
		Str("action", "serving request").
		Str("client", c.ClientIP()).
		Str("method", c.Request.Method).
		Str("path", c.Request.URL.Path).
		Int64("requestBodySize", c.Request.ContentLength).
		Int("responseBodySize", c.Writer.Size()).
		Int("status", c.Writer.Status()).
		TimeDiff("latency", time.Now(), start).
		Err(c.Errors.Last()).
		Send()
}

func recoverMiddleware(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			// Check for a broken connection, as it is not really a condition that warrants a panic stack trace.
			var brokenPipe bool
			if ne, ok := err.(*net.OpError); ok {
				var se *os.SyscallError
				if ok := errors.Is(ne.Err, se); ok {
					if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
						brokenPipe = true
					}
				}
			}

			log.Error().
				Str("entity", "System Recovery").
				Str("action", "recovering from fatal error").
				Err(err.(error)).
				Send()

			if brokenPipe {
				// If the connection is dead, we can't write a status to it.
				c.Abort()
				return
			}

			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"fatal_error": ErrUnexpected.Error()})
		}
	}()

	c.Next()
}
