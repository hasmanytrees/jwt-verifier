package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

func main() {
	if os.Getenv("APP_ENV") == "development" {
		log.Println("Enabling pprof for profiling")
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	u, _ := url.Parse("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_YqcxrkxxP/.well-known/openid-configuration")

	m, err := NewMiddleware([]*url.URL{u})
	if err != nil {
		panic(err)
	}

	e := echo.New()
	e.Use(JWTVerifier(m))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Token has been parsed, validated, and verified")
	})
	e.Logger.Fatal(e.Start(":1323"))
}

func JWTVerifier(m *Middleware) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString := strings.TrimPrefix(c.Request().Header.Get(echo.HeaderAuthorization), "Bearer ")

			start := time.Now()

			_, err := m.Parse(tokenString)
			if err != nil {
				c.String(echo.ErrBadRequest.Code, fmt.Sprintf("Error verifying token: %s\n", err.Error()))
				return err
			}

			duration := time.Since(start)
			slog.Info("Parse Complete", "duration", duration)

			next(c)

			return nil
		}
	}
}
