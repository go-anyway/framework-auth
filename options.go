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
	"fmt"
	"time"

	pkgConfig "github.com/go-anyway/framework-config"

	"github.com/golang-jwt/jwt/v5"
)

// Config JWT 配置结构体（用于从配置文件创建）
type Config struct {
	Enabled       bool               `yaml:"enabled" env:"JWT_ENABLED" default:"true"`
	SecretKey     string             `yaml:"secret_key" env:"JWT_SECRET_KEY" required:"true"`
	Expiration    pkgConfig.Duration `yaml:"expiration" env:"JWT_EXPIRATION" default:"24h"`
	Issuer        string             `yaml:"issuer" env:"JWT_ISSUER" default:"ai-api-market"`
	SigningMethod string             `yaml:"signing_method" env:"JWT_SIGNING_METHOD" default:"HS256"`
}

// Validate 验证 JWT 配置
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("jwt config cannot be nil")
	}
	if !c.Enabled {
		return nil // 如果未启用，不需要验证
	}
	if c.SecretKey == "" {
		return fmt.Errorf("jwt secret_key is required")
	}
	// 验证签名方法
	validMethods := map[string]bool{
		"HS256": true,
		"HS384": true,
		"HS512": true,
		"RS256": true,
		"RS384": true,
		"RS512": true,
		"ES256": true,
		"ES384": true,
		"ES512": true,
	}
	if !validMethods[c.SigningMethod] {
		return fmt.Errorf("jwt signing_method must be one of: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, got %s", c.SigningMethod)
	}
	return nil
}

// ToOptions 转换为 Options
func (c *Config) ToOptions() (*Options, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled {
		return nil, fmt.Errorf("jwt is not enabled")
	}

	expiration := c.Expiration.Duration()
	if expiration == 0 {
		expiration = 24 * time.Hour
	}

	// 解析签名方法
	var signingMethod jwt.SigningMethod
	switch c.SigningMethod {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
	case "HS384":
		signingMethod = jwt.SigningMethodHS384
	case "HS512":
		signingMethod = jwt.SigningMethodHS512
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "ES384":
		signingMethod = jwt.SigningMethodES384
	case "ES512":
		signingMethod = jwt.SigningMethodES512
	default:
		signingMethod = jwt.SigningMethodHS256
	}

	return &Options{
		SecretKey:     c.SecretKey,
		Expiration:    expiration,
		Issuer:        c.Issuer,
		SigningMethod: signingMethod,
	}, nil
}

// ExpirationDuration 返回 time.Duration 类型的 Expiration
func (c *Config) ExpirationDuration() time.Duration {
	return c.Expiration.Duration()
}

// Options JWT 配置选项（内部使用）
type Options struct {
	SecretKey     string
	Expiration    time.Duration
	Issuer        string
	SigningMethod jwt.SigningMethod
}

// DefaultOptions 返回默认 JWT 配置选项
func DefaultOptions(secretKey string) *Options {
	return &Options{
		SecretKey:     secretKey,
		Expiration:    24 * time.Hour,
		Issuer:        "ai-api-market",
		SigningMethod: jwt.SigningMethodHS256,
	}
}
