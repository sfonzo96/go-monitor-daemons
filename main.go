package main

import (
	"github.com/joho/godotenv"
	"github.com/sfonzo96/monitor-go/cmd"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}
	cmd.Execute()
}
