package main

import (
	"net/http"
	"rnd-surajan-cognito-go/environment"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/gin-gonic/gin"
)

type (
	// App struct provides basic information to connect to the
	// Cognito UserPool on AWS.
	App struct {
		CognitoClient   *cognito.CognitoIdentityProvider
		UserPoolID      string
		AppClientID     string
		AppClientSecret string
		Token           string
	}
	User struct {
		// Username is the username decided by the user
		// at signup time. This field is not required but it could
		// be useful to have
		Username string `json:"username" binding:"required"`

		// Password is the password decided by the user
		// at signup time. This field is required and no signup
		// can work without this.
		Password string `json:"password" binding:"required"`

		// Name is not required in Cognito, but we have made it required in this User struct
		Name string `json:"name" binding:"required"`

		// Email is the user email used at signup time.
		// this is a required field and must be used at login time.
	}
	UserRegister struct {
		User  User   `json:"user" binding:"required"`
		Email string `json:"email" binding:"required"`
	}
)

func main() {
	// Initialize Env
	environment.EnvInit()
	// Setup The AWS Region and AWS session
	conf := &aws.Config{Region: aws.String("ap-south-1")}
	mySession := session.Must(session.NewSession(conf))

	// App instance with env
	app := App{
		CognitoClient:   cognito.New(mySession),
		UserPoolID:      environment.GetCognitoUserPoolId(),
		AppClientID:     environment.GetCognitoAppClientId(),
		AppClientSecret: environment.GetCognitoAppClientSecret(),
	}

	// Gin stuff
	r := gin.Default()
	r.GET("", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Learning AWS Cognito",
		})
	})
	r.POST("/signup", app.RegisterUser)
	// Serve on 0.0.0.0:8080 or localhost:8080
	r.Run()
}

func (app *App) RegisterUser(ctx *gin.Context) {
	var newUser UserRegister
	if err := ctx.BindJSON(&newUser); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	cognitoUser := &cognito.SignUpInput{
		Username: aws.String(newUser.User.Username),
		Password: aws.String(newUser.User.Password),
		ClientId: aws.String(app.AppClientID),
		UserAttributes: []*cognito.AttributeType{
			// Email is a required standard attribute provided by Cognito out-of-the-box
			{
				Name:  aws.String("email"),
				Value: aws.String(newUser.Email),
			},
			// "name" is also a standard attribute which is not required by cognito but we have made it required in "User" struct.
			// Standard attributes in Cognito 👉: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
			{
				Name:  aws.String("name"),
				Value: aws.String(newUser.User.Name),
			},
		},
	}
	// Signup in Cognito
	_, err := app.CognitoClient.SignUp(cognitoUser)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": "User Registered Successfully",
	})
}
