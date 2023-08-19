package routes

import (
	"github.com/Padliwinata/mfa-echo/controllers"
	"github.com/labstack/echo/v4"
)

type AuthRouteController struct {
	authController controllers.AuthController
}

func NewAuthRouteController(authController controllers.AuthController) AuthRouteController {
	return AuthRouteController{authController}
}

func (rc *AuthRouteController) AuthRoute(e *echo.Group) {
	router := e.Group("/auth")

	router.POST("/register", rc.authController.SignUpUser)
	router.POST("/login", rc.authController.LoginUser)
	router.POST("/otp/generate", rc.authController.GenerateTOTP)
	router.POST("/otp/verify", rc.authController.VerifyOTP)
	router.POST("/otp/validate", rc.authController.ValidateOTP)
	router.POST("/otp/disable", rc.authController.DisableOTP)

}
