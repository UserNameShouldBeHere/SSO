package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"

	"github.com/UserNameShouldBeHere/SSO/internal/api"
	ssoconfig "github.com/UserNameShouldBeHere/SSO/internal/config"
	sso "github.com/UserNameShouldBeHere/SSO/internal/proto"
	postgresRepo "github.com/UserNameShouldBeHere/SSO/internal/repository/postgres"
	redisRepo "github.com/UserNameShouldBeHere/SSO/internal/repository/redis"
	"github.com/UserNameShouldBeHere/SSO/internal/services"
)

func main() {
	var port int

	flag.IntVar(&port, "p", 4001, "sso port")

	flag.Parse()

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.DebugLevel),
		Development:      true,
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := config.Build()
	if err != nil {
		log.Fatal(err)
	}
	sugarLogger := logger.Sugar()

	pool, err := pgxpool.New(context.Background(), fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		"localhost",
		"5432",
		"postgres",
		"root1234",
		"auth",
	))
	if err != nil {
		log.Fatal(err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	authStorage, err := postgresRepo.NewAuthStorage(pool)
	if err != nil {
		log.Fatal(err)
	}

	myConfig, err := ssoconfig.NewConfig("cmd/config.yml")
	if err != nil {
		log.Fatal(err)
	}

	sessionStorage, err := redisRepo.NewSessionStorage(
		rdb,
		myConfig.Server.SessionExpiration,
		myConfig.Server.FlushInterval)
	if err != nil {
		log.Fatal(err)
	}

	authService, err := services.NewAuthService(authStorage, sessionStorage, sugarLogger, myConfig)
	if err != nil {
		log.Fatal(err)
	}

	s := grpc.NewServer()
	srv, err := api.NewSSOServer(authService)
	if err != nil {
		log.Fatal(err)
	}
	sso.RegisterSSOServer(s, srv)

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
