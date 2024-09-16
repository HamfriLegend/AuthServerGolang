package main

import (
	"AuthServerGolang/api"
	"AuthServerGolang/database"
	"AuthServerGolang/env"
	"log"
)

func main() {
	envs := env.ReadEnv()
	if envs.DBPASS == "" || envs.SECRET == "" || envs.DBHOST == "" || envs.DBPORT == "" || envs.DBUSER == "" || envs.DBNAME == "" {
		log.Fatal("Указаны не все переменныые окружения")
		return
	}
	err := database.InitDatabase(envs.DBUSER, envs.DBPASS, envs.DBNAME, envs.DBHOST, envs.DBPORT)
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных")
	}

	err = api.StartApi(8080)
	if err != nil {
		log.Fatal(err)
	}
}
