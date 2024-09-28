package main

import (
	"Proxy/cert"
	"bufio"
	"bytes"
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
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			return
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("Recovered", r)
				}
			}()
			handleConnection(conn, ca)
		}()
	}
}

type copyWrap struct {
	conn *tls.Conn
	buf  *bytes.Buffer
}

func (wrap copyWrap) Write(p []byte) (n int, err error) {
	write, err := wrap.conn.Write(p)
	if err != nil {
		return write, err
	}
	wrap.buf.Write(p)
	return write, nil
}

func (wrap copyWrap) FindRequest() []*http.Request {
	reader := bufio.NewReader(wrap.buf)
	res := make([]*http.Request, 0)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				//fmt.Println(err, "in find req")
				return res
			} else {
				fmt.Println()
			}
		}
		res = append(res, request)
		fmt.Println(request.RequestURI)
	}
}

func (wrap copyWrap) FindResponse(reqs []*http.Request) []*http.Response {
	reader := bufio.NewReader(wrap.buf)
	res := make([]*http.Response, 0)
	for {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				if len(res) != len(reqs) {
					panic("hz")
				}
				return res
			}
		}
		res = append(res, response)
	}
}

func handleHTTPS(conn net.Conn, r *http.Request, ca cert.CertificateWithPrivate) {
	host := r.URL.Host
	//fmt.Println(host, r.Method)
	go conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	tlsConn2Chan := make(chan *tls.Conn)
	go func() {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		conn2, err := d.DialContext(ctx, "tcp", r.URL.Host)
		if err != nil {
			log.Printf("Failed to dial: %v", err)
			tlsConn2Chan <- nil
		}
		tlsConn2 := tls.Client(conn2, &tls.Config{ServerName: strings.Split(host, ":")[0]})
		tlsConn2Chan <- tlsConn2
	}()

	hostReplaced := strings.Split(strings.ReplaceAll(r.Host, ".", "-"), ":")[0]
	if _, err := os.Stat("certs/hosts/" + hostReplaced + ".crt"); errors.Is(err, os.ErrNotExist) {
		_, err = cert.CreateCert(hostReplaced, ca, "certs/hosts")
		if err != nil {
			return
		}
	}
	serverCert, err := tls.LoadX509KeyPair("certs/hosts/"+hostReplaced+".crt", "certs/hosts/"+hostReplaced+"-PRIVATE.key")
	if err != nil {
		fmt.Println(err)
		return
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	tlsConn := tls.Server(conn, config)

	tlsConn2 := <-tlsConn2Chan
	buf1 := copyWrap{
		conn: tlsConn,
		buf:  new(bytes.Buffer),
	}
	buf2 := copyWrap{
		conn: tlsConn2,
		buf:  new(bytes.Buffer),
	}
	reqResChan := make(chan []*http.Request)
	go func() {
		io.Copy(buf2, tlsConn)
		reqResChan <- buf2.FindRequest()
	}()
	io.Copy(buf1, tlsConn2)
	buf1.FindResponse(<-reqResChan)
	return
}

func handleConnection(conn net.Conn, ca cert.CertificateWithPrivate) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println(err)
			return
		}
	}(conn)
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
	//initDB()
	startListener(ca)
}
