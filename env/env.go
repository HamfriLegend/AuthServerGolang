package env

import (
	"github.com/joho/godotenv"
	"os"
)

type Env struct {
	DBHOST string
	DBPORT string
	DBUSER string
	DBPASS string
	DBNAME string
	SECRET string
}

func ReadEnv() Env {
	godotenv.Load(".env")
	dbhost := os.Getenv("DBHOST")
	dbport := os.Getenv("DBPORT")
	dbuser := os.Getenv("DBUSER")
	dbpassword := os.Getenv("DBPASS")
	dbname := os.Getenv("DBNAME")
	secret := os.Getenv("SECRET")
	return Env{dbhost, dbport, dbuser, dbpassword, dbname, secret}
}
