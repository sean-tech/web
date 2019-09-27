package services

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sean-tech/web/config"
	"time"
)

const (
	KEY_CTX_USERID 		= "KEY_CTX_USERID"
	KEY_CTX_USERNAME 	= "KEY_CTX_USERNAME"
	KEY_CTX_PASSWORD 	= "KEY_CTX_PASSWORD"
)

var jwtSecret = []byte(config.AppSetting.JwtSecret)

type Claims struct {
	UserId uint64 	`json:"userId"`
	UserName string `json:"userName"`
	Password string `json:"password"`
	jwt.StandardClaims
}

func GenerateToken(userId uint64, userName, password string) (string, error) {
	expireTime := time.Now().Add(3 * time.Hour)
	claims := Claims{
		UserId:			userId,
		UserName:       userName,
		Password:       password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			Issuer:    "Team",
		},
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString(jwtSecret)
	return token, err
}

func ParseToken(token string) (*Claims, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if tokenClaims != nil {
		if claims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
			return claims, nil
		}
	}
	return nil, err
}

type middleWare int
var  MiddleWare = new(middleWare)

func (this *middleWare) Jwt() gin.HandlerFunc {
	handler := func(ctx *gin.Context) {
		g := Gin{ctx}
		var statusCode StatusCode = STATUS_CODE_SUCCESS
		// token
		token := ctx.GetHeader("Authorization")
		if token == "" {
			g.ResponseCode(STATUS_CODE_AUTH_CHECK_TOKEN_FAILED, nil)
			ctx.Abort()
			return
		}
		// token parse
		claims, err := ParseToken(token)
		if err != nil {
			statusCode = STATUS_CODE_AUTH_CHECK_TOKEN_FAILED
		} else if time.Now().Unix() > claims.ExpiresAt {
			statusCode = STATUS_CODE_AUTH_CHECK_TOKEN_TIMEOUT
		} else {
			ctx.Set(KEY_CTX_USERID, claims.UserId)
			ctx.Set(KEY_CTX_USERNAME, claims.UserName)
			ctx.Set(KEY_CTX_PASSWORD, claims.Password)
		}
		if statusCode != STATUS_CODE_SUCCESS {
			g.ResponseCode(statusCode, nil)
			ctx.Abort()
			return
		}
		// next
		ctx.Next()
	}
	return handler
}