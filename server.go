package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

func main() {
	u, _ := url.Parse("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_YqcxrkxxP/.well-known/openid-configuration")

	m, err := NewMiddleware([]*url.URL{u}, WithRefresh)
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
