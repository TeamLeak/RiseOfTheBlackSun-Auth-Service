package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/disintegration/imaging"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Config описывает конфигурацию сервиса.
type Config struct {
	Server struct {
		Port   string `yaml:"port"`
		Domain string `yaml:"domain"`
		Cors   struct {
			AllowedOrigins []string `yaml:"allowedOrigins"`
			AllowedMethods []string `yaml:"allowedMethods"`
			AllowedHeaders []string `yaml:"allowedHeaders"`
		} `yaml:"cors"`
	} `yaml:"server"`
	Database struct {
		Type string `yaml:"type"`
		DSN  string `yaml:"dsn"`
	} `yaml:"database"`
	Auth struct {
		JWTSecret              string `yaml:"jwtSecret"`
		TokenExpirationMinutes int    `yaml:"tokenExpirationMinutes"`
		ResetTokenExpiration   int    `yaml:"resetTokenExpiration"` // в минутах
	} `yaml:"auth"`
	SMTP struct {
		Host             string `yaml:"host"`
		Port             int    `yaml:"port"`
		Username         string `yaml:"username"`
		Password         string `yaml:"password"`
		Sender           string `yaml:"sender"`
		ResetPasswordURL string `yaml:"resetPasswordURL"` // Базовый URL для ссылки сброса пароля
	} `yaml:"smtp"`
}

// LoadConfig загружает конфигурацию из YAML-файла.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}

// User описывает модель пользователя.
type User struct {
	ID               uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	Username         string     `json:"username"`
	Email            string     `gorm:"uniqueIndex" json:"email"`
	Password         string     `json:"-"` // Храним хэш пароля
	Avatar           string     `json:"avatar"`
	LastLoginAt      *time.Time `json:"lastLoginAt"`
	TwoFactorEnabled bool       `json:"twoFactorEnabled" gorm:"default:false"`
	TwoFactorSecret  string     `json:"-"`                  // Секрет для 2FA (TOTP)
	TokenVersion     int        `json:"-" gorm:"default:0"` // Для инвалидации JWT токенов
}

// Cosmetic описывает модель косметического предмета (скина или плаща).
type Cosmetic struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt time.Time `json:"uploadDate"`
	UpdatedAt time.Time `json:"updatedAt"`
	UserID    uuid.UUID `gorm:"type:uuid;index" json:"-"`
	Name      string    `json:"name"`
	Type      string    `json:"type" gorm:"type:varchar(10)"` // skin или cape
	URL       string    `json:"url"`
	Active    bool      `json:"active" gorm:"default:false"`
}

// LoginHistory описывает историю входов пользователя.
type LoginHistory struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt time.Time `json:"date"`
	UserID    uuid.UUID `gorm:"type:uuid;index" json:"-"`
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent"`
	Location  string    `json:"location"` // Локация (может определяться по IP)
	Browser   string    `json:"browser"`  // Извлекается из User-Agent
}

var (
	db                  *gorm.DB
	config              *Config
	tokenBlacklistCache *cache.Cache // Кэш для хранения инвалидированных токенов (logout)
	resetTokenCache     *cache.Cache // Кэш для хранения токенов сброса пароля

	// Ограничения для косметических предметов
	MAX_SKINS = 7 // Максимальное количество скинов на пользователя
	MAX_CAPES = 5 // Максимальное количество плащей на пользователя
)

// hashPassword генерирует bcrypt хэш пароля.
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// checkPassword сравнивает пароль с его bcrypt хэшем.
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// generateJWT генерирует JWT токен для пользователя.
func generateJWT(user User) (string, error) {
	expirationTime := time.Now().Add(time.Duration(config.Auth.TokenExpirationMinutes) * time.Minute)
	claims := jwt.MapClaims{
		"user_id":   user.ID.String(),
		"email":     user.Email,
		"token_ver": user.TokenVersion, // Версия токена для инвалидации
		"exp":       expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.Auth.JWTSecret))
}

// authMiddleware проверяет наличие и валидность JWT токена.
func authMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Отсутствует заголовок авторизации", "code": http.StatusUnauthorized})
		return
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Некорректный формат заголовка", "code": http.StatusUnauthorized})
		return
	}
	tokenStr := parts[1]

	// Проверяем, что токен не находится в черном списке
	if _, found := tokenBlacklistCache.Get(tokenStr); found {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Токен недействителен", "code": http.StatusUnauthorized})
		return
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrInvalidKey
		}
		return []byte(config.Auth.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Недействительный токен", "code": http.StatusUnauthorized})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Недействительный токен", "code": http.StatusUnauthorized})
		return
	}
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Недействительный токен", "code": http.StatusUnauthorized})
		return
	}
	uid, err := uuid.Parse(userIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Недействительный токен", "code": http.StatusUnauthorized})
		return
	}
	var user User
	if err := db.First(&user, "id = ?", uid).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Пользователь не найден", "code": http.StatusUnauthorized})
		return
	}
	// Сохраняем пользователя в контексте
	c.Set("user", user)
	c.Set("tokenString", tokenStr)
	c.Next()
}

// sendResetEmail отправляет письмо для сброса пароля с использованием SMTP.
func sendResetEmail(recipient, resetToken string) error {
	subject := "Сброс пароля"
	// Используем URL формата reset-password?token=xxx вместо reset-password/token
	resetLink := fmt.Sprintf("%s?token=%s", config.SMTP.ResetPasswordURL, resetToken)
	body := fmt.Sprintf("Для сброса пароля перейдите по ссылке: %s", resetLink)
	// Формируем сообщение
	msg := []byte("From: " + config.SMTP.Sender + "\r\n" +
		"To: " + recipient + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")
	addr := fmt.Sprintf("%s:%d", config.SMTP.Host, config.SMTP.Port)
	auth := smtp.PlainAuth("", config.SMTP.Username, config.SMTP.Password, config.SMTP.Host)
	return smtp.SendMail(addr, auth, config.SMTP.Sender, []string{recipient}, msg)
}

// loginHandler обрабатывает POST /login.
func loginHandler(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Некорректные данные запроса", "code": http.StatusBadRequest})
		return
	}

	var user User
	if err := db.First(&user, "email = ?", req.Email).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Неверные учетные данные", "code": http.StatusUnauthorized})
		return
	}

	if !checkPassword(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Неверные учетные данные", "code": http.StatusUnauthorized})
		return
	}

	now := time.Now()
	user.LastLoginAt = &now
	db.Save(&user)

	token, err := generateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось создать токен", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"avatar":      user.Avatar,
			"createdAt":   user.CreatedAt,
			"lastLoginAt": user.LastLoginAt,
		},
	})
}

// registerHandler обрабатывает POST /register.
func registerHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Некорректные данные запроса", "code": http.StatusBadRequest})
		return
	}

	// Проверяем существование пользователя с таким email или username
	var count int64
	db.Model(&User{}).Where("email = ?", req.Email).Or("username = ?", req.Username).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"message": "Пользователь с таким email или именем уже существует", "code": http.StatusConflict})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка хеширования пароля", "code": http.StatusInternalServerError})
		return
	}

	user := User{
		ID:        uuid.New(),
		Username:  req.Username,
		Email:     req.Email,
		Password:  hashedPassword,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось создать пользователя", "code": http.StatusInternalServerError})
		return
	}

	token, err := generateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось создать токен", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		"user": gin.H{
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"avatar":      user.Avatar,
			"createdAt":   user.CreatedAt,
			"lastLoginAt": user.LastLoginAt,
		},
	})
}

// logoutHandler обрабатывает POST /auth/logout.
func logoutHandler(c *gin.Context) {
	tokenStr, exists := c.Get("tokenString")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Токен не найден", "code": http.StatusUnauthorized})
		return
	}
	// Добавляем токен в черный список до истечения срока его действия
	tokenBlacklistCache.Set(tokenStr.(string), true, time.Duration(config.Auth.TokenExpirationMinutes)*time.Minute)
	c.JSON(http.StatusOK, gin.H{"message": "Успешный выход"})
}

// getUserProfileHandler обрабатывает GET /user/profile.
func getUserProfileHandler(c *gin.Context) {
	userI, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Пользователь не найден", "code": http.StatusUnauthorized})
		return
	}
	user := userI.(User)
	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"avatar":      user.Avatar,
		"createdAt":   user.CreatedAt,
		"lastLoginAt": user.LastLoginAt,
	})
}

// updateUserProfileHandler обрабатывает PATCH /user/profile.
func updateUserProfileHandler(c *gin.Context) {
	userI, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Пользователь не найден", "code": http.StatusUnauthorized})
		return
	}
	user := userI.(User)

	var req struct {
		Username string `json:"username"`
		Avatar   string `json:"avatar"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Некорректные данные запроса", "code": http.StatusBadRequest})
		return
	}
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}
	user.UpdatedAt = time.Now()

	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось обновить профиль", "code": http.StatusInternalServerError})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"avatar":      user.Avatar,
		"createdAt":   user.CreatedAt,
		"lastLoginAt": user.LastLoginAt,
	})
}

// forgotPasswordHandler обрабатывает POST /forgot-password.
func forgotPasswordHandler(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Некорректные данные запроса", "code": http.StatusBadRequest})
		return
	}

	var user User
	if err := db.First(&user, "email = ?", req.Email).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Пользователь не найден", "code": http.StatusNotFound})
		return
	}

	// Генерируем токен сброса пароля и сохраняем его в кэше
	resetToken := uuid.New().String()
	resetTokenCache.Set(resetToken, user.ID.String(), time.Duration(config.Auth.ResetTokenExpiration)*time.Minute)

	// Отправка email для сброса пароля
	if err := sendResetEmail(user.Email, resetToken); err != nil {
		log.Printf("Ошибка отправки email сброса пароля для %s: %v", user.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось отправить письмо для сброса пароля", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Инструкции по сбросу пароля отправлены на email"})
}

// resetPasswordHandler обрабатывает POST /reset-password/{token}.
func resetPasswordHandler(c *gin.Context) {
	resetToken := c.Param("token")
	userIDStr, found := resetTokenCache.Get(resetToken)
	if !found {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Недействительный или просроченный токен", "code": http.StatusUnauthorized})
		return
	}

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Некорректные данные запроса", "code": http.StatusBadRequest})
		return
	}

	var user User
	if err := db.First(&user, "id = ?", userIDStr.(string)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Пользователь не найден", "code": http.StatusNotFound})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка хеширования пароля", "code": http.StatusInternalServerError})
		return
	}
	user.Password = hashedPassword
	user.UpdatedAt = time.Now()

	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Не удалось обновить пароль", "code": http.StatusInternalServerError})
		return
	}

	resetTokenCache.Delete(resetToken)
	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно изменен"})
}

// uploadAvatarHandler обрабатывает POST /user/avatar.
func uploadAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Получаем файл из формы
	file, err := c.FormFile("avatar")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Не удалось получить файл аватара", "code": http.StatusBadRequest})
		return
	}

	// Проверяем размер файла (максимум 2 МБ)
	if file.Size > 2*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Размер файла превышает 2 МБ", "code": http.StatusBadRequest})
		return
	}

	// Проверяем тип файла (только изображения)
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неподдерживаемый формат файла. Используйте JPG, PNG или GIF", "code": http.StatusBadRequest})
		return
	}

	// Создаем директорию для хранения аватаров, если она не существует
	avatarsDir := "./avatars"
	if _, err := os.Stat(avatarsDir); os.IsNotExist(err) {
		os.MkdirAll(avatarsDir, 0755)
	}

	// Генерируем уникальное имя файла с использованием UUID пользователя
	fileName := fmt.Sprintf("%s%s", user.ID.String(), ext)
	filePath := filepath.Join(avatarsDir, fileName)

	// Открываем загруженный файл
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при обработке файла", "code": http.StatusInternalServerError})
		return
	}
	defer src.Close()

	// Создаем файл на сервере
	dst, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сохранении файла", "code": http.StatusInternalServerError})
		return
	}
	defer dst.Close()

	// Копируем содержимое загруженного файла
	if _, err = io.Copy(dst, src); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сохранении файла", "code": http.StatusInternalServerError})
		return
	}

	// Обрабатываем изображение - изменяем размер и обрезаем до квадрата для аватара
	src.Close()
	dst.Close()

	// Открываем сохраненное изображение для обработки
	img, err := imaging.Open(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при обработке изображения", "code": http.StatusInternalServerError})
		return
	}

	// Обрезаем изображение до квадрата и изменяем размер до 128x128
	img = imaging.Fill(img, 128, 128, imaging.Center, imaging.Lanczos)

	// Сохраняем обработанное изображение
	if err := imaging.Save(img, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сохранении обработанного изображения", "code": http.StatusInternalServerError})
		return
	}

	// Обновляем URL аватара пользователя в БД с полным доменом из конфигурации
	avatarURL := fmt.Sprintf("%s/avatars/%s", config.Server.Domain, fileName)
	user.Avatar = avatarURL

	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при обновлении профиля", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Аватар успешно обновлен",
		"avatar":  avatarURL,
	})
}

// getCosmeticsHandler обрабатывает GET /user/cosmetics.
func getCosmeticsHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Получаем все косметические предметы пользователя
	var cosmetics []Cosmetic
	if err := db.Where("user_id = ?", user.ID).Find(&cosmetics).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при получении косметических предметов", "code": http.StatusInternalServerError})
		return
	}

	// Подсчет количества скинов и плащей
	var skinCount, capeCount int
	for _, item := range cosmetics {
		if item.Type == "skin" {
			skinCount++
		} else if item.Type == "cape" {
			capeCount++
		}
	}

	// Формируем информацию об ограничениях
	limits := gin.H{
		"skins": gin.H{"used": skinCount, "total": MAX_SKINS},
		"capes": gin.H{"used": capeCount, "total": MAX_CAPES},
	}

	c.JSON(http.StatusOK, gin.H{
		"items":  cosmetics,
		"limits": limits,
	})
}

// uploadCosmeticHandler обрабатывает POST /user/cosmetics.
func uploadCosmeticHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Получаем файл из формы
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Не удалось получить файл", "code": http.StatusBadRequest})
		return
	}

	// Получаем параметры из формы
	name := c.PostForm("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Необходимо указать название", "code": http.StatusBadRequest})
		return
	}

	cosmeticType := c.PostForm("type")
	if cosmeticType != "skin" && cosmeticType != "cape" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Тип должен быть 'skin' или 'cape'", "code": http.StatusBadRequest})
		return
	}

	// Проверяем размер файла (максимум 1 МБ)
	if file.Size > 1*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Размер файла превышает 1 МБ", "code": http.StatusBadRequest})
		return
	}

	// Проверяем количество уже загруженных предметов
	var count int64
	db.Model(&Cosmetic{}).Where("user_id = ? AND type = ?", user.ID, cosmeticType).Count(&count)

	var maxItems int
	if cosmeticType == "skin" {
		maxItems = MAX_SKINS
	} else {
		maxItems = MAX_CAPES
	}

	if count >= int64(maxItems) {
		c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("Достигнут лимит предметов типа %s (%d)", cosmeticType, maxItems), "code": http.StatusBadRequest})
		return
	}

	// Создаем директорию для хранения косметических предметов
	cosmeticsDir := filepath.Join(".", "cosmetics", cosmeticType+"s")
	if _, err := os.Stat(cosmeticsDir); os.IsNotExist(err) {
		os.MkdirAll(cosmeticsDir, 0755)
	}

	// Генерируем уникальное имя файла
	itemID := uuid.New()
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext == "" {
		ext = ".png" // По умолчанию считаем PNG
	}
	fileName := fmt.Sprintf("%s%s", itemID.String(), ext)
	filePath := filepath.Join(cosmeticsDir, fileName)

	// Сохраняем файл
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сохранении файла", "code": http.StatusInternalServerError})
		return
	}

	// Создаем запись в БД с полным доменом из конфигурации
	relativePath := fmt.Sprintf("%s/cosmetics/%ss/%s", config.Server.Domain, cosmeticType, fileName)
	cosmetic := Cosmetic{
		ID:     itemID,
		UserID: user.ID,
		Name:   name,
		Type:   cosmeticType,
		URL:    relativePath,
		Active: false, // По умолчанию не активен
	}

	if err := db.Create(&cosmetic).Error; err != nil {
		// Удаляем файл в случае ошибки
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сохранении данных", "code": http.StatusInternalServerError})
		return
	}

	// Подсчитываем количество скинов и плащей для ответа
	var skinCount, capeCount int64
	db.Model(&Cosmetic{}).Where("user_id = ? AND type = ?", user.ID, "skin").Count(&skinCount)
	db.Model(&Cosmetic{}).Where("user_id = ? AND type = ?", user.ID, "cape").Count(&capeCount)

	// Формируем ответ
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("%s успешно загружен", cosmeticType),
		"item":    cosmetic,
		"limits": gin.H{
			"skins": gin.H{"used": skinCount, "total": MAX_SKINS},
			"capes": gin.H{"used": capeCount, "total": MAX_CAPES},
		},
	})
}

// activateCosmeticHandler обрабатывает POST /user/cosmetics/:id/activate
func activateCosmeticHandler(c *gin.Context) {
	user := c.MustGet("user").(User)
	cosmeticID := c.Param("id")

	// Проверяем, что ID валидный UUID
	itemID, err := uuid.Parse(cosmeticID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный формат ID", "code": http.StatusBadRequest})
		return
	}

	// Получаем косметический предмет
	var cosmetic Cosmetic
	if err := db.Where("id = ? AND user_id = ?", itemID, user.ID).First(&cosmetic).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"message": "Косметический предмет не найден", "code": http.StatusNotFound})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при получении данных", "code": http.StatusInternalServerError})
		}
		return
	}

	// Сначала деактивируем все косметические предметы этого типа
	if err := db.Model(&Cosmetic{}).Where("user_id = ? AND type = ?", user.ID, cosmetic.Type).Update("active", false).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при обновлении данных", "code": http.StatusInternalServerError})
		return
	}

	// Теперь активируем выбранный предмет
	if err := db.Model(&cosmetic).Update("active", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при активации предмета", "code": http.StatusInternalServerError})
		return
	}

	// Формируем ответ
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("%s успешно активирован", cosmetic.Type),
		"item":    cosmetic,
	})
}

// deleteCosmeticHandler обрабатывает DELETE /user/cosmetics/:id
func deleteCosmeticHandler(c *gin.Context) {
	user := c.MustGet("user").(User)
	cosmeticID := c.Param("id")

	// Проверяем, что ID валидный UUID
	itemID, err := uuid.Parse(cosmeticID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный формат ID", "code": http.StatusBadRequest})
		return
	}

	// Получаем косметический предмет
	var cosmetic Cosmetic
	if err := db.Where("id = ? AND user_id = ?", itemID, user.ID).First(&cosmetic).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"message": "Косметический предмет не найден", "code": http.StatusNotFound})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при получении данных", "code": http.StatusInternalServerError})
		}
		return
	}

	// Получаем путь к файлу
	// Извлекаем имя файла из URL
	fileURL := cosmetic.URL
	parts := strings.Split(fileURL, "/")
	fileName := parts[len(parts)-1]

	// Формируем полный путь
	cosmeticsDir := filepath.Join(".", "cosmetics", cosmetic.Type+"s")
	filePath := filepath.Join(cosmeticsDir, fileName)

	// Удаляем запись из БД
	if err := db.Delete(&cosmetic).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при удалении данных", "code": http.StatusInternalServerError})
		return
	}

	// Удаляем файл
	// Не возвращаем ошибку, если файл не существует
	_ = os.Remove(filePath)

	// Подсчитываем количество скинов и плащей для ответа
	var skinCount, capeCount int64
	db.Model(&Cosmetic{}).Where("user_id = ? AND type = ?", user.ID, "skin").Count(&skinCount)
	db.Model(&Cosmetic{}).Where("user_id = ? AND type = ?", user.ID, "cape").Count(&capeCount)

	// Формируем ответ
	c.JSON(http.StatusOK, gin.H{
		"message":    fmt.Sprintf("%s успешно удален", cosmetic.Type),
		"deleted_id": itemID,
		"limits": gin.H{
			"skins": gin.H{"used": skinCount, "total": MAX_SKINS},
			"capes": gin.H{"used": capeCount, "total": MAX_CAPES},
		},
	})
}

// get2FAStatusHandler обрабатывает GET /user/2fa/status
func get2FAStatusHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	c.JSON(http.StatusOK, gin.H{
		"enabled": user.TwoFactorEnabled,
		"secret":  user.TwoFactorSecret, // Возвращаем секрет только если 2FA уже настроен
	})
}

// enable2FAHandler обрабатывает POST /user/2fa/enable
func enable2FAHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Проверяем, что 2FA еще не включен
	if user.TwoFactorEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"message": "2FA уже включен", "code": http.StatusBadRequest})
		return
	}

	// Получаем код подтверждения из запроса
	var req struct {
		Code   string `json:"code"`
		Secret string `json:"secret,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный формат данных", "code": http.StatusBadRequest})
		return
	}

	// Если секрет не существует, генерируем новый
	secret := req.Secret
	if secret == "" && user.TwoFactorSecret == "" {
		// Создаем новый секрет
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "RiseOfTheBlackSun",
			AccountName: user.Email,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при генерации ключа", "code": http.StatusInternalServerError})
			return
		}

		// Сохраняем новый секрет в БД без активации
		user.TwoFactorSecret = key.Secret()
		if err := db.Model(&user).Update("two_factor_secret", key.Secret()).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сохранении секрета", "code": http.StatusInternalServerError})
			return
		}

		// Возвращаем новый секрет
		c.JSON(http.StatusOK, gin.H{
			"message": "Сгенерирован новый секрет",
			"secret":  key.Secret(),
			"qr_code": key.URL(),
		})
		return
	}

	// Используем существующий секрет
	if secret == "" {
		secret = user.TwoFactorSecret
	}

	// Проверяем код
	valid := totp.Validate(req.Code, secret)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный код", "code": http.StatusBadRequest})
		return
	}

	// Включаем 2FA
	if err := db.Model(&user).Updates(map[string]interface{}{
		"two_factor_enabled": true,
		"two_factor_secret":  secret,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при включении 2FA", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA успешно включен"})
}

// disable2FAHandler обрабатывает POST /user/2fa/disable
func disable2FAHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Проверяем, что 2FA включен
	if !user.TwoFactorEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"message": "2FA не включен", "code": http.StatusBadRequest})
		return
	}

	// Получаем код подтверждения и пароль
	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный формат данных", "code": http.StatusBadRequest})
		return
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Неверный пароль", "code": http.StatusUnauthorized})
		return
	}

	// Проверяем код 2FA
	valid := totp.Validate(req.Code, user.TwoFactorSecret)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный код 2FA", "code": http.StatusBadRequest})
		return
	}

	// Отключаем 2FA
	if err := db.Model(&user).Updates(map[string]interface{}{
		"two_factor_enabled": false,
		"two_factor_secret":  "", // Удаляем секрет
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при отключении 2FA", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA успешно отключен"})
}

// getLoginHistoryHandler обрабатывает GET /user/login-history
func getLoginHistoryHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Получаем историю входов пользователя
	var history []LoginHistory

	// По умолчанию возвращаем последние 10 записей
	limit := 10
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	if err := db.Where("user_id = ?", user.ID).Order("created_at DESC").Limit(limit).Find(&history).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при получении истории входов", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}

// changePasswordHandler обрабатывает POST /user/change-password
func changePasswordHandler(c *gin.Context) {
	user := c.MustGet("user").(User)

	// Получаем текущий и новый пароль
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Неверный формат данных. Новый пароль должен быть не менее 8 символов", "code": http.StatusBadRequest})
		return
	}

	// Проверяем текущий пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Неверный текущий пароль", "code": http.StatusUnauthorized})
		return
	}

	// Хешируем новый пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при хешировании пароля", "code": http.StatusInternalServerError})
		return
	}

	// Обновляем пароль в базе данных
	if err := db.Model(&user).Update("password", string(hashedPassword)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при обновлении пароля", "code": http.StatusInternalServerError})
		return
	}

	// При смене пароля можно также выполнить выход из всех сессий
	// Для этого меняем значение tokenVersion
	if err := db.Model(&user).Update("token_version", user.TokenVersion+1).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Ошибка при сбросе сессий", "code": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно изменен"})
}

func main() {
	migrateFlag := flag.Bool("migrate", false, "Выполнить миграции базы данных и выйти")
	flag.Parse()

	var err error
	config, err = LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Инициализация подключения к БД
	var dialector gorm.Dialector
	switch config.Database.Type {
	case "postgres":
		dialector = postgres.Open(config.Database.DSN)
	case "sqlite":
		dialector = sqlite.Open(config.Database.DSN)
	default:
		log.Fatalf("Неподдерживаемый тип базы данных: %s", config.Database.Type)
	}

	db, err = gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		log.Fatalf("Ошибка подключения к базе данных: %v", err)
	}

	// Миграция моделей
	if err := db.AutoMigrate(&User{}, &Cosmetic{}, &LoginHistory{}); err != nil {
		log.Fatalf("Ошибка миграции: %v", err)
	}

	if *migrateFlag {
		log.Println("Миграция успешно выполнена!")
		return
	}

	// Инициализация in-memory кэшей
	tokenBlacklistCache = cache.New(time.Duration(config.Auth.TokenExpirationMinutes)*time.Minute, 10*time.Minute)
	resetTokenCache = cache.New(time.Duration(config.Auth.ResetTokenExpiration)*time.Minute, 10*time.Minute)

	// Инициализация Gin и настройка CORS
	router := gin.Default()
	publicCors := cors.Config{
		AllowOrigins:     config.Server.Cors.AllowedOrigins,
		AllowMethods:     config.Server.Cors.AllowedMethods,
		AllowHeaders:     config.Server.Cors.AllowedHeaders,
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(publicCors))

	// Эндпоинты аутентификации
	router.POST("/login", loginHandler)
	router.POST("/register", registerHandler)
	router.POST("/auth/logout", authMiddleware, logoutHandler)
	router.GET("/user/profile", authMiddleware, getUserProfileHandler)
	router.PATCH("/user/profile", authMiddleware, updateUserProfileHandler)
	router.POST("/forgot-password", forgotPasswordHandler)
	router.POST("/reset-password/:token", resetPasswordHandler)

	// Эндпоинты аватара
	router.POST("/user/avatar", authMiddleware, uploadAvatarHandler)
	router.Static("/avatars", "./avatars")

	// Эндпоинты косметических предметов
	router.GET("/user/cosmetics", authMiddleware, getCosmeticsHandler)
	router.POST("/user/cosmetics", authMiddleware, uploadCosmeticHandler)
	router.POST("/user/cosmetics/:id/activate", authMiddleware, activateCosmeticHandler)
	router.DELETE("/user/cosmetics/:id", authMiddleware, deleteCosmeticHandler)
	router.Static("/cosmetics", "./cosmetics")

	// Эндпоинты безопасности
	router.GET("/user/2fa/status", authMiddleware, get2FAStatusHandler)
	router.POST("/user/2fa/enable", authMiddleware, enable2FAHandler)
	router.POST("/user/2fa/disable", authMiddleware, disable2FAHandler)
	router.GET("/user/login-history", authMiddleware, getLoginHistoryHandler)
	router.POST("/user/change-password", authMiddleware, changePasswordHandler)

	// Запуск сервера с graceful shutdown
	port := config.Server.Port
	if port == "" {
		port = "3000"
	}
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Запуск сервера в отдельной горутине
	go func() {
		log.Printf("Сервер запущен на порту %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Ошибка запуска сервера: %v", err)
		}
	}()

	// Ожидание сигнала для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Получен сигнал завершения, закрываем сервер...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Ошибка graceful shutdown: %v", err)
	}
	log.Println("Сервер завершил работу")
}
