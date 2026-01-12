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

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrTokenMissing token 缺失错误
	ErrTokenMissing = errors.New("token is missing")
	// ErrTokenInvalid token 无效错误
	ErrTokenInvalid = errors.New("token is invalid")
	// ErrTokenExpired token 过期错误
	ErrTokenExpired = errors.New("token is expired")
)

// JWTClaims JWT 声明
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
