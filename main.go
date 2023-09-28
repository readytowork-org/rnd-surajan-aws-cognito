package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Learning AWS Cognito",
		})
	})
	// Serve on 0.0.0.0:8080 or localhost:8080
	r.Run()
}
