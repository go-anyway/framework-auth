// Copyright 2025 zampo.

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestDefaultOptions(t *testing.T) {
	secretKey := "test-secret-key"
	opts := DefaultOptions(secretKey)

	if opts.SecretKey != secretKey {
		t.Errorf("SecretKey = %v, want %v", opts.SecretKey, secretKey)
	}
	if opts.Expiration != 24*time.Hour {
		t.Errorf("Expiration = %v, want %v", opts.Expiration, 24*time.Hour)
	}
	if opts.Issuer != "ai-api-market" {
		t.Errorf("Issuer = %v, want %v", opts.Issuer, "ai-api-market")
	}
	if opts.SigningMethod == nil {
		t.Error("SigningMethod should not be nil")
	}
}

func TestNewJWTManager(t *testing.T) {
	opts := &Options{
		SecretKey:     "test-secret",
		Expiration:    time.Hour,
		Issuer:        "test-issuer",
		SigningMethod: jwt.SigningMethodHS256,
	}

	manager := NewJWTManager(opts)

	if manager == nil {
		t.Fatal("NewJWTManager returned nil")
	}
	if manager.opts.SecretKey != opts.SecretKey {
		t.Errorf("opts.SecretKey = %v, want %v", manager.opts.SecretKey, opts.SecretKey)
	}
}

func TestGenerateToken(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))

	token, err := manager.GenerateToken("user123", "testuser", "admin")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if token == "" {
		t.Error("GenerateToken() returned empty token")
	}
}

func TestValidateToken_Valid(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))

	token, err := manager.GenerateToken("user123", "testuser", "admin")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("UserID = %v, want %v", claims.UserID, "user123")
	}
	if claims.Username != "testuser" {
		t.Errorf("Username = %v, want %v", claims.Username, "testuser")
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %v, want %v", claims.Role, "admin")
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))

	_, err := manager.ValidateToken("invalid-token")
	if err == nil {
		t.Error("ValidateToken() should return error for invalid token")
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("ValidateToken() error = %v, want ErrTokenInvalid", err)
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	manager1 := NewJWTManager(DefaultOptions("secret-key-1"))
	manager2 := NewJWTManager(DefaultOptions("secret-key-2"))

	token, err := manager1.GenerateToken("user123", "testuser", "admin")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = manager2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should return error for token signed with different secret")
	}
}

func TestValidateToken_Expired(t *testing.T) {
	opts := &Options{
		SecretKey:     "test-secret-key",
		Expiration:    -time.Hour,
		Issuer:        "test-issuer",
		SigningMethod: jwt.SigningMethodHS256,
	}
	manager := NewJWTManager(opts)

	token, err := manager.GenerateToken("user123", "testuser", "admin")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = manager.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should return error for expired token")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("ValidateToken() error = %v, want ErrTokenExpired", err)
	}
}

func TestJWTAuthMiddleware_NoHeader(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.JWTAuthMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	middleware(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusUnauthorized)
	}
	if c.IsAborted() == false {
		t.Error("Context should be aborted")
	}
}

func TestJWTAuthMiddleware_InvalidFormat(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.JWTAuthMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "InvalidFormat token123")

	middleware(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusUnauthorized)
	}
	if c.IsAborted() == false {
		t.Error("Context should be aborted")
	}
}

func TestJWTAuthMiddleware_ValidToken(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.JWTAuthMiddleware()

	token, _ := manager.GenerateToken("user123", "testuser", "admin")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	middleware(c)

	if c.IsAborted() {
		t.Error("Context should not be aborted for valid token")
	}
	if c.GetString("user_id") != "user123" {
		t.Errorf("user_id = %v, want %v", c.GetString("user_id"), "user123")
	}
	if c.GetString("username") != "testuser" {
		t.Errorf("username = %v, want %v", c.GetString("username"), "testuser")
	}
	if c.GetString("role") != "admin" {
		t.Errorf("role = %v, want %v", c.GetString("role"), "admin")
	}
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.JWTAuthMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer invalid-token")

	middleware(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusUnauthorized)
	}
	if c.IsAborted() == false {
		t.Error("Context should be aborted for invalid token")
	}
}

func TestOptionalJWTAuthMiddleware_NoHeader(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.OptionalJWTAuthMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	middleware(c)

	if c.IsAborted() {
		t.Error("Context should not be aborted when no header is present")
	}
}

func TestOptionalJWTAuthMiddleware_InvalidFormat(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.OptionalJWTAuthMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "InvalidFormat token123")

	middleware(c)

	if c.IsAborted() {
		t.Error("Context should not be aborted when token format is invalid")
	}
}

func TestOptionalJWTAuthMiddleware_ValidToken(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.OptionalJWTAuthMiddleware()

	token, _ := manager.GenerateToken("user456", "optional_user", "user")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	middleware(c)

	if c.IsAborted() {
		t.Error("Context should not be aborted for valid token")
	}
	if c.GetString("user_id") != "user456" {
		t.Errorf("user_id = %v, want %v", c.GetString("user_id"), "user456")
	}
}

func TestOptionalJWTAuthMiddleware_InvalidToken(t *testing.T) {
	manager := NewJWTManager(DefaultOptions("test-secret-key"))
	middleware := manager.OptionalJWTAuthMiddleware()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer invalid-token")

	middleware(c)

	if c.IsAborted() {
		t.Error("Context should not be aborted when token is invalid")
	}
}
