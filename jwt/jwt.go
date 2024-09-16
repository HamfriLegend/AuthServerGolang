package jwt

import (
	"AuthServerGolang/database"
	"crypto/rand"
	"encoding/base64"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Payload struct {
	Guid      string
	IP        string
	RefreshID int
}

func GenerateTokens(guid string, ip string, secret string, user database.UserAuth) Tokens {
	//Создание нового токена в БД
	refreshTokenRaw := make([]byte, 32)
	rand.Read(refreshTokenRaw)
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenRaw)
	refreshTokenHash, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	refreshTokenRec := database.RefreshToken{
		RefreshToken: string(refreshTokenHash),
		Active:       true,
	}
	database.DB.Create(&refreshTokenRec)

	accessTokenRaw := jwt.New(jwt.SigningMethodHS512)
	accessTokenRaw.Claims = jwt.MapClaims{
		"guid":       guid,
		"ip":         ip,
		"refresh_id": refreshTokenRec.ID,
		"exp":        time.Now().Add(time.Minute * 5).Unix(),
	}

	accessToken, _ := accessTokenRaw.SignedString([]byte(secret))

	//Сброс прошлого токена если был
	DeleteTokens(&user)

	//Обновление информации
	user.RefreshTokenID = &refreshTokenRec.ID
	user.Ipaddress = ip
	database.DB.Save(&user)
	return Tokens{accessToken, refreshToken}
}

// GetPayoad функция для получения payload токена без проверки подписи
func GetPayoad(accessToken string) Payload {
	token, _ := jwt.Parse(accessToken, nil)
	claims, _ := token.Claims.(jwt.MapClaims)
	return Payload{claims["guid"].(string), claims["ip"].(string), int(claims["refresh_id"].(float64))}
}

// DeleteTokens функция для сброса токенов
func DeleteTokens(user *database.UserAuth) {
	if user.RefreshTokenID != nil {
		database.DB.Model(&database.RefreshToken{}).Where("id = ?", user.RefreshTokenID).Update("active", false)
	}
}
