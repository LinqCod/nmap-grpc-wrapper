package main

import (
	"fmt"
	"github.com/linqcod/nmap-grpc-wrapper/config"
	api "github.com/linqcod/nmap-grpc-wrapper/pkg/api"
	"github.com/linqcod/nmap-grpc-wrapper/pkg/netvuln"
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
	api.RegisterNetVulnServiceServer(s, &netvuln.Server{})

	log.Printf("server is listening to %s:%s", cfg.Server.Host, cfg.Server.Port)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("error. Failed to serve: %v", err)
	}
}
