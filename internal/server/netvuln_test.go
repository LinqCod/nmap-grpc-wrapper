package server

import (
	"github.com/linqcod/nmap-grpc-wrapper/pb"
	"golang.org/x/net/context"
	"testing"
)

var tests = []struct {
	targets  []string
	tcpPorts []int32
	want     string
}{
	{
		targets:  []string{"localhost"},
		tcpPorts: []int32{},
		want:     "Hello world",
	},
}

func TestCheckVuln(t *testing.T) {
	s := &Server{}

	for _, tt := range tests {
		req := &pb.CheckVulnRequest{}
		resp, err := s.CheckVuln(context.Background(), req)
		if err != nil {
			t.Errorf("CheckVuln() got unexpected error")
		}
		if resp.String() != tt.want {
			t.Errorf("CheckVuln()=%v, wanted %v", resp.String(), tt.want)
		}
	}
}
