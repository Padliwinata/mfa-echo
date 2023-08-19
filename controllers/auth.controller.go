package controllers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Padliwinata/mfa-echo/models"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type AuthController struct {
	DB *gorm.DB
}

func NewAuthController(DB *gorm.DB) AuthController {
	return AuthController{DB}
}

func (ac *AuthController) SignUpUser(c echo.Context) error {
	var payload *models.RegisterUserInput

	if err := c.Bind(&payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": err.Error()})
	}

	newUser := models.User{
		Name:     payload.Name,
		Email:    strings.ToLower(payload.Email),
		Password: payload.Password,
	}

	result := ac.DB.Create(&newUser)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
		return c.JSON(http.StatusConflict, map[string]interface{}{"status": "fail", "message": "Email already exists, please use another email address"})
	} else if result.Error != nil {
		return c.JSON(http.StatusBadGateway, map[string]interface{}{"status": "error", "message": result.Error.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{"status": "success", "message": "Registered successfully, please login"})
}

func (ac *AuthController) LoginUser(c echo.Context) error {
	var payload *models.LoginUserInput

	if err := c.Bind(&payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": err.Error()})
	}

	var user models.User
	result := ac.DB.First(&user, "email = ?", strings.ToLower(payload.Email))
	if result.Error != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
	}

	userResponse := map[string]interface{}{
		"id":          user.ID.String(),
		"name":        user.Name,
		"email":       user.Email,
		"otp_enabled": user.Otp_enabled,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"status": "success", "user": userResponse})
}

func (ac *AuthController) GenerateTOTP(c echo.Context) error {
	var payload *models.OTPInput

	if err := c.Bind(&payload); err != nil {
		data := map[string]interface{}{
			"status":  "fail",
			"message": err.Error(),
		}

		c.JSON(http.StatusBadRequest, data)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "iam-mfa.com",
		AccountName: "example@gmail.com",
		SecretSize:  15,
	})

	if err != nil {
		return err
	}

	var user models.User
	result := ac.DB.First(&user, "id=?", payload.UserId)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
		return result.Error
	}

	dataToUpdate := models.User{
		Otp_secret:   key.Secret(),
		Otp_auth_url: key.URL(),
	}

	ac.DB.Model(&user).Updates(dataToUpdate)

	otpResponse := map[string]interface{}{
		"base32":      key.Secret(),
		"otpauth_url": key.URL(),
	}

	return c.JSON(http.StatusOK, otpResponse)
}

func (ac *AuthController) VerifyOTP(c echo.Context) error {
	var payload *models.OTPInput

	if err := c.Bind(&payload); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": err.Error()})
		return err
	}

	data := map[string]interface{}{
		"status":  "fail",
		"message": "Token invalid or user doesn't exist",
	}

	var user models.User
	result := ac.DB.First(&user, "id=?", payload.UserId)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, data)
		return result.Error
	}

	valid := totp.Validate(payload.Token, user.Otp_secret)
	if !valid {
		c.JSON(http.StatusBadRequest, data)
		return errors.New("Bad Request")
	}

	dataToUpdate := models.User{
		Otp_enabled:  true,
		Otp_verified: true,
	}

	ac.DB.Model(&user).Updates(dataToUpdate)

	userResponse := map[string]interface{}{
		"id":          user.ID.String(),
		"name":        user.Name,
		"email":       user.Email,
		"otp_enabled": user.Otp_enabled,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"otp_verified": true, "user": userResponse})
}

func (ac *AuthController) ValidateOTP(c echo.Context) error {
	var payload *models.OTPInput

	if err := c.Bind(&payload); err != nil {
		data := map[string]interface{}{
			"status":  "fail",
			"message": err.Error(),
		}

		c.JSON(http.StatusBadRequest, data)
		return err
	}

	data := map[string]interface{}{
		"status":  "fail",
		"message": "Token invalid or user doesn't exist",
	}

	var user models.User
	result := ac.DB.First(&user, "id=?", payload.UserId)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, data)
		return result.Error
	}

	valid := totp.Validate(payload.Token, user.Otp_secret)
	if !valid {
		c.JSON(http.StatusBadRequest, data)
		return errors.New("Bad Request")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"otp_valid": true})

}

func (ac *AuthController) DisableOTP(c echo.Context) error {
	var payload *models.OTPInput

	if err := c.Bind(&payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": err.Error()})
	}

	var user models.User
	result := ac.DB.First(&user, "id = ?", payload.UserId)
	if result.Error != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "User doesn't exist"})
	}

	user.Otp_enabled = false
	ac.DB.Save(&user)

	userResponse := map[string]interface{}{
		"id":          user.ID.String(),
		"name":        user.Name,
		"email":       user.Email,
		"otp_enabled": user.Otp_enabled,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"otp_disabled": true, "user": userResponse})
}
