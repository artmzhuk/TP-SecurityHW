package db

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"unicode/utf8"

	_ "github.com/lib/pq"
)

func InitDB() *sql.DB {
	db, err := sql.Open("postgres", "user=postgres dbname=postgres password=postgres host=postgres port=5432 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func StoreRequest(db *sql.DB, r *http.Request, res chan int) {
	var requestID int
	query := `
		INSERT INTO proxy.requests (scheme, host, path, URI, body, raw)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`
	err := db.QueryRow(query, r.URL.Scheme, r.Host, r.URL.Path, r.URL.String(), "", "").Scan(&requestID)
	if err != nil {
		res <- -1
	}

	for key, values := range r.Header {
		for _, value := range values {
			_, err := db.Exec(`
				INSERT INTO proxy.request_headers (request_id, key, value)
				VALUES ($1, $2, $3)`, requestID, key, value)
			if err != nil {
				res <- -1
			}
		}
	}
	if r.Method == "GET" {
		myUrl, _ := url.Parse(r.URL.String())
		params, _ := url.ParseQuery(myUrl.RawQuery)
		for key, value := range params {
			for _, pValue := range value {
				_, err := db.Exec(`
				INSERT INTO proxy.parameters (request_id, key, value)
				VALUES ($1, $2, $3)`, requestID, key, pValue)
				if err != nil {
					res <- -1
				}
			}
		}
	}
	res <- requestID
}

func StoreResponse(db *sql.DB, reqID chan int, resp *http.Response) error {
	var responseID int

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bodyStr := ""
	if utf8.Valid(bodyBytes) {
		bodyStr = string(bodyBytes)
	}
	reqIDValue := <-reqID
	query := `
		INSERT INTO proxy.responses (status, body, request_id)
		VALUES ($1, $2, $3)
		RETURNING id`
	err = db.QueryRow(query, resp.StatusCode, bodyStr, reqIDValue).Scan(&responseID)
	if err != nil {
		return fmt.Errorf("failed to store response: %w", err)
	}

	for key, values := range resp.Header {
		for _, value := range values {
			_, err := db.Exec(`
				INSERT INTO proxy.response_headers (response_id, key, value)
				VALUES ($1, $2, $3)`, responseID, key, value)
			if err != nil {
				return fmt.Errorf("failed to store response header: %w", err)
			}
		}
	}

	return nil
}
