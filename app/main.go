package main

import (
	"github.com/RianIhsan/go-sess-auth/models"
	"github.com/RianIhsan/go-sess-auth/routes"
)

func main() {
	models.Setup()
	routes.Setup()
}
