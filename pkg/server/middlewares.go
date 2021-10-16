package server

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
	if (c.Writer.Status() % 500) < 100 {
		log.Error().
			Str("client", c.ClientIP()).
			Str("method", c.Request.Method).
			Str("uri", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			TimeDiff("latency", time.Now(), start).
			Send()
	} else {
		log.Info().
			Str("client", c.ClientIP()).
			Str("method", c.Request.Method).
			Str("uri", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			TimeDiff("latency", time.Now(), start).
			Send()
	}
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
				Stack().
				Caller().
				Err(err.(error)).
				Send()

			if brokenPipe {
				// If the connection is dead, we can't write a status to it.
				c.Abort()
				return
			}

			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"fatal_error": ErrUnexpectedFailure.Error()})
		}
	}()

	c.Next()
}
