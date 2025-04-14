package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hasmanytrees/jwt-verifier/jwt"
	"github.com/labstack/echo/v4"
)

func main() {
	u, _ := url.Parse("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_YqcxrkxxP/.well-known/openid-configuration")

	kc := jwt.NewKeyCache()
	err := kc.AddProvider(u)
	if err != nil {
		panic(err)
	}

	e := echo.New()
	e.Use(JWTVerifier(kc))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Token has been parsed, validated, and verified")
	})
	e.Logger.Fatal(e.Start(":1323"))
}

func JWTVerifier(kc *jwt.KeyCache) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString := strings.TrimPrefix(c.Request().Header.Get(echo.HeaderAuthorization), "Bearer ")

			start := time.Now()

			_, err := jwt.Parse(tokenString, kc.KeyFunc)
			if err != nil {
				c.String(echo.ErrBadRequest.Code, fmt.Sprintf("Error verifying token: %s\n", err.Error()))
				return err
			}

			duration := time.Since(start)
			fmt.Printf("Parse duration: %v\n", duration)

			next(c)

			return nil
		}
	}
}
