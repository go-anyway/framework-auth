// Copyright 2025 zampo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// @contact  zampo3380@gmail.com

package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	pkgErrors "github.com/go-anyway/framework-errors"
	"github.com/go-anyway/framework-gateway"
	"github.com/go-anyway/framework-log"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// JWTManager JWT 管理器
type JWTManager struct {
	opts *Options
}

// NewJWTManager 创建新的 JWT 管理器
func NewJWTManager(opts *Options) *JWTManager {
	return &JWTManager{
		opts: opts,
	}
}

// NewJWTManagerFromConfig 从配置创建 JWT 管理器
func NewJWTManagerFromConfig(cfg *Config) (*JWTManager, error) {
	opts, err := cfg.ToOptions()
	if err != nil {
		return nil, err
	}
	return NewJWTManager(opts), nil
}

// GenerateToken 生成 JWT token
func (m *JWTManager) GenerateToken(userID, username, role string) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.opts.Expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    m.opts.Issuer,
		},
	}

	token := jwt.NewWithClaims(m.opts.SigningMethod, claims)
	return token.SignedString([]byte(m.opts.SecretKey))
}

// ValidateToken 验证 JWT token
func (m *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(m.opts.SecretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrTokenInvalid
}

// JWTAuthMiddleware 创建 JWT 认证中间件
func (m *JWTManager) JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 Header 中获取 token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gateway.StandardResponse{
				Code: pkgErrors.CodeUnauthorized,
				Msg:  "缺少认证令牌",
			})
			c.Abort()
			return
		}

		// 解析 Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gateway.StandardResponse{
				Code: pkgErrors.CodeUnauthorized,
				Msg:  "无效的认证格式，请使用: Bearer <token>",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := m.ValidateToken(tokenString)
		if err != nil {
			logger := log.FromContext(c.Request.Context())
			logger.Warn("JWT validation failed",
				zap.Error(err),
				zap.String("path", c.Request.URL.Path),
			)

			code := pkgErrors.CodeUnauthorized
			msg := "认证令牌无效"
			if errors.Is(err, ErrTokenExpired) {
				code = pkgErrors.CodeTokenExpired
				msg = "认证令牌已过期"
			}

			c.JSON(http.StatusUnauthorized, gateway.StandardResponse{
				Code: code,
				Msg:  msg,
			})
			c.Abort()
			return
		}

		// 将用户信息存储到 context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}

// OptionalJWTAuthMiddleware 创建可选的 JWT 认证中间件（token 不存在时不报错）
func (m *JWTManager) OptionalJWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]
		claims, err := m.ValidateToken(tokenString)
		if err == nil {
			c.Set("user_id", claims.UserID)
			c.Set("username", claims.Username)
			c.Set("role", claims.Role)
		}

		c.Next()
	}
}
