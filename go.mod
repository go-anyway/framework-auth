module github.com/go-anyway/framework-auth

go 1.25.4

require (
	github.com/go-anyway/framework-config v1.0.0
	github.com/go-anyway/framework-errors v1.0.0
	github.com/go-anyway/framework-gateway v1.0.0
	github.com/go-anyway/framework-log v1.0.0
	github.com/golang-jwt/jwt/v5 v5.3.0
)

replace (
	github.com/go-anyway/framework-config => ../core/config
	github.com/go-anyway/framework-errors => ../core/errors
	github.com/go-anyway/framework-gateway => ../core/gateway
	github.com/go-anyway/framework-log => ../core/log
)
