package db

import (
	"database/sql"
	"log"
)

func InitDB() *sql.DB {
	db, err := sql.Open("postgres", "user=postgres dbname=proxy password=postgres host=localhost port=5432 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	return db
}
