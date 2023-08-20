package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Padliwinata/mfa-echo/models"
	"github.com/deta/deta-go/service/base"
	"github.com/labstack/echo/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/pquerna/otp/totp"
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
)

type AuthController struct {
	DB *gorm.DB
	db *base.Base
}

func NewAuthController(DB *gorm.DB, db *base.Base) AuthController {
	return AuthController{DB, db}
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
	newUser.BeforeCreate()

	// newUser := map[string]interface{}{
	// 	"name":     payload.Name,
	// 	"email":    payload.Email,
	// 	"password": payload.Password,
	// }
	// result := ac.DB.Create(&newUser)
	_, err := ac.db.Put(newUser)

	// if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
	// 	return c.JSON(http.StatusConflict, map[string]interface{}{"status": "fail", "message": "Email already exists, please use another email address"})
	// } else if result.Error != nil {
	// 	return c.JSON(http.StatusBadGateway, map[string]interface{}{"status": "error", "message": result.Error.Error()})
	// }

	if err != nil && strings.Contains(err.Error(), "duplicate key value violates unique") {
		return c.JSON(http.StatusConflict, map[string]interface{}{"status": "fail", "message": "Email already exists, please use another email address"})
	} else if err != nil {
		return c.JSON(http.StatusBadGateway, map[string]interface{}{"status": "error", "message": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{"status": "success", "message": "Registered successfully, please login"})
}

func (ac *AuthController) LoginUser(c echo.Context) error {
	var payload *models.LoginUserInput

	if err := c.Bind(&payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": err.Error()})
	}

	var user models.User
	// result := ac.DB.First(&user, "email = ?", strings.ToLower(payload.Email))
	query := base.Query{
		{"email?contains": strings.ToLower(payload.Email)},
	}

	var result []map[string]interface{}
	_, err := ac.db.Fetch(&base.FetchInput{
		Q:    query,
		Dest: &result,
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
		return err
	}

	if len(result) <= 0 {
		return errors.New("Invalid email or password")
	}

	mapstructure.Decode(result[0], &user)
	user.ID = uuid.Must(uuid.FromString(fmt.Sprintf("%v", result[0]["id"])))

	// if result.Error != nil {
	// 	return c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
	// }

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
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
		return err
	}

	var user models.User
	// result := ac.DB.First(&user, "id=?", payload.UserId)
	query := base.Query{
		{"id?contains": payload.UserId},
	}
	// if result.Error != nil {
	// 	c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
	// 	return result.Error
	// }
	var result []map[string]interface{}
	_, err = ac.db.Fetch(&base.FetchInput{
		Q:    query,
		Dest: &result,
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Invalid email or password"})
		return err
	}

	if len(result) <= 0 {
		return errors.New("Invalid email or password")
	}

	mapstructure.Decode(result[0], &user)

	updates := base.Updates{
		"otp_secret":   key.Secret(),
		"otp_auth_url": key.URL(),
	}

	err = ac.db.Update(user.Key, updates)

	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Failed to update"})
		return err
	}

	// dataToUpdate := models.User{
	// 	Otp_secret:   key.Secret(),
	// 	Otp_auth_url: key.URL(),
	// }

	// ac.DB.Model(&user).Updates(dataToUpdate)

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
	// result := ac.DB.First(&user, "id=?", payload.UserId)
	query := base.Query{
		{"id?contains": payload.UserId},
	}

	// if result.Error != nil {
	// 	c.JSON(http.StatusBadRequest, data)
	// 	return result.Error
	// }

	var result []map[string]interface{}
	_, err := ac.db.Fetch(&base.FetchInput{
		Q:    query,
		Dest: &result,
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, data)
		return err
	}
	mapstructure.Decode(result[0], &user)
	user.ID = uuid.Must(uuid.FromString(fmt.Sprintf("%v", result[0]["id"])))

	valid := totp.Validate(payload.Token, user.Otp_secret)
	if !valid {
		c.JSON(http.StatusBadRequest, data)
		return errors.New("Bad Request")
	}

	// dataToUpdate := models.User{
	// 	Otp_enabled:  true,
	// 	Otp_verified: true,
	// }

	updates := base.Updates{
		"otp_enabled":  true,
		"otp_verified": true,
	}

	err = ac.db.Update(user.Key, updates)

	// ac.DB.Model(&user).Updates(dataToUpdate)

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
	// result := ac.DB.First(&user, "id=?", payload.UserId)
	query := base.Query{
		{"id?contains": payload.UserId},
	}

	var result []map[string]interface{}
	_, err := ac.db.Fetch(&base.FetchInput{
		Q:    query,
		Dest: &result,
	})

	mapstructure.Decode(result[0], &user)
	user.ID = uuid.Must(uuid.FromString(fmt.Sprintf("%v", result[0]["id"])))

	if err != nil {
		c.JSON(http.StatusBadRequest, data)
		return err
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
	// result := ac.DB.First(&user, "id = ?", payload.UserId)

	query := base.Query{
		{"id?contains": payload.UserId},
	}

	var result []map[string]interface{}
	_, err := ac.db.Fetch(&base.FetchInput{
		Q:    query,
		Dest: &result,
	})

	mapstructure.Decode(result[0], &user)
	user.ID = uuid.Must(uuid.FromString(fmt.Sprintf("%v", result[0]["id"])))

	if err != nil || len(result) <= 0 {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "User doesn't exist"})
		return err
	}

	user.Otp_enabled = false
	// ac.DB.Save(&user)
	updates := base.Updates{
		"otp_enabled": false,
	}

	err = ac.db.Update(user.Key, updates)

	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"status": "fail", "message": "Failed to disable"})
		return err
	}

	userResponse := map[string]interface{}{
		"id":          user.ID.String(),
		"name":        user.Name,
		"email":       user.Email,
		"otp_enabled": user.Otp_enabled,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"otp_disabled": true, "user": userResponse})
}
