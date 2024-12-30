package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	gen "github.com/UserNameShouldBeHere/SSO/internal/proto"
	"google.golang.org/grpc"
)

func main() {
	var port int

	flag.IntVar(&port, "p", 4001, "sso port")

	flag.Parse()

	s := grpc.NewServer()
	srv := gen.UnimplementedSSOServer{}
	gen.RegisterSSOServer(s, srv)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-sigint
		s.GracefulStop()
		if err := listener.Close(); err != nil {
			fmt.Printf("Server shutdown error: %v\n", err)
		}
	}()

	fmt.Printf("Starting server at localhost%s\n", fmt.Sprintf(":%d", port))

	err = s.Serve(listener)
	if err != nil {
		log.Fatal(err)
	}

	<-stopped

	fmt.Println("Server stopped")
}
