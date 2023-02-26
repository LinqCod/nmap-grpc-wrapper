package server

import (
	"github.com/linqcod/nmap-grpc-wrapper/pb"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"strings"
	"testing"
)

type expectation struct {
	out string
}

var tests = map[string]struct {
	targets  []string
	tcpPorts []int32
	expected expectation
}{
	"Must_Success": {
		targets:  []string{"localhost"},
		tcpPorts: []int32{},
		expected: expectation{
			out: "results:{target:\"127.0.0.1\"services:{name:\"ipp\"version:\"2.4\"tcp_port:631vulns:{identifier:\"CVE-2022-26691\"cvss_score:7.2}vulns:{identifier:\"CVE-2022-26691\"}}}",
		},
	},
}

func TestCheckVuln(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() {
		lis.Close()
	})

	srv := grpc.NewServer()
	t.Cleanup(func() {
		srv.Stop()
	})

	s := Server{}
	pb.RegisterNetVulnServiceServer(srv, &s)

	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("error while serving listener: %v", err)
		}
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.DialContext(
		context.Background(),
		"",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	t.Cleanup(func() {
		conn.Close()
	})
	if err != nil {
		t.Fatalf("error while dialing with context %v", err)
	}

	client := pb.NewNetVulnServiceClient(conn)

	for scenario, tt := range tests {
		t.Run(scenario, func(t *testing.T) {
			res, err := client.CheckVuln(context.Background(), &pb.CheckVulnRequest{
				Targets:  tt.targets,
				TcpPorts: tt.tcpPorts,
			})
			if err != nil {
				t.Fatalf("error while checking vuln: %v", err)
			}

			if strings.ReplaceAll(res.String(), " ", "") != tt.expected.out {
				t.Fatalf("Unexpected value. Want: %s,\nGot: %s", tt.expected.out, res)
			}
		})
	}
}
