package main

import (
	"fmt"
	"github.com/linqcod/nmap-grpc-wrapper/config"
	"github.com/linqcod/nmap-grpc-wrapper/internal/server"
	"github.com/linqcod/nmap-grpc-wrapper/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"os"
)

func main() {
	cfgPath, err := config.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := config.NewConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	logLevel, err := log.ParseLevel(cfg.Logger.Level)
	if err != nil {
		log.Errorf("error while parsing log level: %v", err)
	}

	log.SetLevel(logLevel)
	log.SetOutput(os.Stdout)

	listener, err := net.Listen(
		cfg.Server.Network,
		fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
	)
	if err != nil {
		log.Fatalf("error while listening port: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterNetVulnServiceServer(s, &server.Server{})

	log.Printf("server is listening to %s:%s", cfg.Server.Host, cfg.Server.Port)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("error. Failed to serve: %v", err)
	}
}
