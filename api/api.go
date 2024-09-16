package api

import (
	"AuthServerGolang/database"
	"AuthServerGolang/env"
	"AuthServerGolang/jwt"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type LoginRequest struct {
	Guid string `json:"guid"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type ApiResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LoginHandler Обработчик роута api/login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	//Проверка на POST запрос
	if r.Method != "POST" {
		http.Error(w, "Post Only", 405)
		return
	}

	//Проверка тела запроса
	var request LoginRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil || request.Guid == "" {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	envs := env.ReadEnv()
	ip := r.RemoteAddr
	//Проверка на наличие такого пользователя в БД
	var user database.UserAuth
	result := database.DB.Where("guid = ?", request.Guid).First(&user)
	if result.Error != nil {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}
	//Генерация новых токенов
	tokens := jwt.GenerateTokens(request.Guid, ip, envs.SECRET, user)

	//Отправка запроса
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(ApiResponse{tokens.AccessToken, tokens.RefreshToken})
	if err != nil {
		http.Error(w, "Что-то пошло не так", http.StatusInternalServerError)
		return
	}
}

// RefreshHandler обработчик роута api/refresh
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	//Проверка на POST Запрос
	if r.Method != "POST" {
		http.Error(w, "Post Only", 405)
		return
	}
	//Проверка наличия заголовка авторизации
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}
	//Проверка JWT авторизации
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, bearerPrefix)

	//Проверка тела запроса на наличие Refresh Токена
	var request RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil || request.RefreshToken == "" {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}

	refreshToken := request.RefreshToken
	//Расшифровка payload части access токена чтобы узнать id и ip
	payload := jwt.GetPayoad(accessToken)

	//Проверка на наличие такого пользователя
	var user database.UserAuth
	result := database.DB.Where("guid = ?", payload.Guid).First(&user)
	if result.Error != nil {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}
	if user.RefreshTokenID == nil {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}
	//Проверка на то что пользователь залогинен (имеет refresh токен и access связан с ним)
	var userRefreshToken database.RefreshToken
	result = database.DB.Where("id = ?", user.RefreshTokenID).First(&userRefreshToken)

	//Проверка на совпадение токенов
	errRToken := bcrypt.CompareHashAndPassword([]byte(userRefreshToken.RefreshToken), []byte(refreshToken))

	if errRToken != nil { //Проверка не пройдена
		var allRefreshTokens []database.RefreshToken
		result = database.DB.Find(&allRefreshTokens)
		if result.Error == nil {
			//Проверяем на совпадение токенов, если совпали деактивируем их
			//(кто-то попытался воспользоваться старым или чужим токеном)
			for _, oneRefreshToken := range allRefreshTokens {
				errRToken = bcrypt.CompareHashAndPassword([]byte(oneRefreshToken.RefreshToken), []byte(refreshToken))
				if errRToken == nil {
					oneRefreshToken.Active = false
					database.DB.Save(&oneRefreshToken)
				}
			}
		}
		//Так как токены не совпали сбрасываем их у пользователя

		jwt.DeleteTokens(&user)
		user.RefreshTokenID = nil
		database.DB.Save(&user)
		http.Error(w, "Неверный refresh токен", 401)
		return
	}

	//Токен должен быть активен
	if result.Error != nil && !userRefreshToken.Active {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}
	//Проверка связи двух токенов
	if *user.RefreshTokenID != payload.RefreshID {
		http.Error(w, "Ошибка авторизации", 401)
		return
	}
	//Если IP отличается от предыдущего, то высылыем сообщение на почту пользователя
	if (user.Ipaddress != payload.IP) || (user.Ipaddress != r.RemoteAddr) {
		log.Println("Кто-то попытался войти с другого IP адреса: " + payload.IP +
			"\nЕсли это были не вы ....\nСообщение отправлено на почту: " + user.Mail)
	}

	//Если ошибок не было то генерируем новые токены
	//И сбрасываем старые
	envs := env.ReadEnv()
	newTokens := jwt.GenerateTokens(payload.Guid, payload.IP, envs.SECRET, user)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(ApiResponse{newTokens.AccessToken, newTokens.RefreshToken})
	if err != nil {
		http.Error(w, "Что-то пошло не так", http.StatusInternalServerError)
		return
	}
}

func StartApi(port int) error {
	http.HandleFunc("/api/login", LoginHandler)
	http.HandleFunc("/api/refresh", RefreshHandler)

	log.Println("Listening on localhost:" + strconv.Itoa(port))
	err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
	if err != nil {
		return err
	} else {
		return nil
	}
}
