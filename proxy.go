package main

import (
	"Proxy/cert"
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func startListener(ca cert.CertificateWithPrivate) {
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
		go handleConnection(conn, ca)
	}
}
func handleHTTPS(conn net.Conn, r *http.Request, ca cert.CertificateWithPrivate) {
	host := r.URL.Host
	//port := r.URL.Port()
	fmt.Println(host)

	hostReplaced := strings.Split(strings.ReplaceAll(r.Host, ".", "-"), ":")[0]
	if _, err := os.Stat("certs/hosts/" + hostReplaced + ".crt"); errors.Is(err, os.ErrNotExist) {
		_, err = cert.CreateCert(hostReplaced, ca, "certs/hosts")
		if err != nil {
			return
		}
	}
	serverCert, err := tls.LoadX509KeyPair("certs/hosts/"+hostReplaced+".crt", "certs/hosts/"+hostReplaced+"-PRIVATE.key")

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	tlsConn := tls.Server(conn, config)
	reader := bufio.NewReader(tlsConn)
	requestFromClient, err := http.ReadRequest(reader)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn2, err := d.DialContext(ctx, "tcp", r.URL.Host)

	if err != nil {
		log.Printf("Failed to dial: %v", err)
	}
	defer conn2.Close()
	err = requestFromClient.Write(conn2)
	if err != nil {
		log.Println(err)
		return
	}
	io.Copy(tlsConn, conn2)

	/*r.Write(conn2)
	reader2 := bufio.NewReader(conn2)
	if err != nil {
		return
	}
	resp, _ := io.ReadAll(reader2)
	fmt.Println(string(resp))*/
	return
}

func handleConnection(conn net.Conn, ca cert.CertificateWithPrivate) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		log.Println(err)
		return
	}
	if request.Method == "CONNECT" {
		handleHTTPS(conn, request, ca)
		return
	}

	request.Header.Del("Proxy-Connection")
	url := request.URL.Host
	if request.URL.Port() == "" {
		url += ":80"
	}
	fmt.Println(url)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
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
	ca := cert.CertificateWithPrivate{}
	if _, err := os.Stat("certs/ca.crt"); errors.Is(err, os.ErrNotExist) {
		ca, err = cert.CreateCA("certs")
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		ca, err = cert.OpenCert("certs/ca")
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	/*	_, err := cert.CreateCert("mail.ru", ca, "certs/hosts")
		if err != nil {
			fmt.Println(err)
			return
		}*/
	startListener(ca)
}
