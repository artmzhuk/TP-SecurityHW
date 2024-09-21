package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func startListener() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go handleConnection(conn)
	}
}
func handleHTTPS(conn net.Conn, connReader *bufio.Reader, r *http.Request) {
	//host := r.Host
	//port := r.URL.Port()
	conn2, err := net.Dial("tcp", r.URL.Host)
	if err != nil {
		fmt.Println(err)
		return
	}
	conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	io.Copy(conn2, conn)

	/*r.Write(conn2)
	reader2 := bufio.NewReader(conn2)
	if err != nil {
		return
	}
	resp, _ := io.ReadAll(reader2)
	fmt.Println(string(resp))*/
	return
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		log.Println(err)
		return
	}
	if request.Method == "CONNECT" {
		handleHTTPS(conn, reader, request)
		return
	}

	request.Header.Del("Proxy-Connection")
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	url := request.URL.Host
	if request.URL.Port() == "" {
		url += ":80"
	}
	fmt.Println(url)
	conn2, err := d.DialContext(ctx, "tcp", url)
	if err != nil {
		log.Printf("Failed to dial: %v", err)
	}
	defer conn2.Close()

	err = request.WriteProxy(conn2)
	if err != nil {
		log.Println(err)
		return
	}
	io.Copy(conn, conn2)
}

func main() {
	//certs.CreateCA()

	startListener()
}
