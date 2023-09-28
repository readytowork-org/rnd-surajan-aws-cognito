package environment

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func EnvInit() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Some error occured. Err: %s", err)
		panic("Could not load env.")
	}
}

func GetCognitoUserPoolId() string {
	return os.Getenv("COGNITO_USER_POOL_ID")
}

func GetCognitoAppClientId() string {
	return os.Getenv("COGNITO_APP_CLIENT_ID")
}

func GetCognitoAppClientSecret() string {
	return os.Getenv("COGNITO_APP_CLIENT_SECRET")
}
