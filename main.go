package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Padliwinata/mfa-echo/controllers"
	"github.com/Padliwinata/mfa-echo/models"
	"github.com/Padliwinata/mfa-echo/routes"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	DB *gorm.DB
	e  *echo.Echo

	AuthController      controllers.AuthController
	AuthRouteController routes.AuthRouteController
)

func init() {
	var err error
	DB, err := gorm.Open(sqlite.Open("golang.db"), &gorm.Config{})
	DB.AutoMigrate(&models.User{})

	if err != nil {
		log.Fatal("Failed to connect to the Database")
	}
	fmt.Println("Connected successfully")

	e = echo.New()

	AuthController = controllers.NewAuthController(DB)
	AuthRouteController = routes.NewAuthRouteController(AuthController)

}

func main() {

	corsConfig := middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	}

	e.Use(middleware.CORSWithConfig(corsConfig))

	router := e.Group("/api")
	router.GET("/healthchecker", func(c echo.Context) error {
		data := map[string]interface{}{
			"message": "ok",
		}

		return c.JSON(http.StatusOK, data)
	})
	AuthRouteController.AuthRoute(router)
	e.Logger.Fatal(e.Start(":8000"))
}
