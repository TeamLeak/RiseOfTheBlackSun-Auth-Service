package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Config описывает конфигурацию сервиса.
type Config struct {
	Server struct {
		Port string `yaml:"port"`
		Cors struct {
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
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	Username    string     `json:"username"`
	Email       string     `gorm:"uniqueIndex" json:"email"`
	Password    string     `json:"-"` // Храним хэш пароля
	Avatar      string     `json:"avatar"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
}

var (
	db                  *gorm.DB
	config              *Config
	tokenBlacklistCache *cache.Cache // Кэш для хранения инвалидированных токенов (logout)
	resetTokenCache     *cache.Cache // Кэш для хранения токенов сброса пароля
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
		"user_id": user.ID.String(),
		"email":   user.Email,
		"exp":     expirationTime.Unix(),
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
	resetLink := fmt.Sprintf("%s/%s", strings.TrimRight(config.SMTP.ResetPasswordURL, "/"), resetToken)
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

	// Миграция модели пользователя
	if err := db.AutoMigrate(&User{}); err != nil {
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
