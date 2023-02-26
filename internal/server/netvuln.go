package server

import (
	"context"
	"github.com/linqcod/nmap-grpc-wrapper/internal/service"
	"github.com/linqcod/nmap-grpc-wrapper/pb"
)

type Server struct {
	pb.UnimplementedNetVulnServiceServer
	service service.VulnChecker
}

func New(service service.VulnChecker) *Server {
	return &Server{
		service: service,
	}
}

func (s *Server) CheckVuln(ctx context.Context, in *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error) {
	vulnCheckRequest := &service.VulnCheckRequest{
		Targets:  in.Targets,
		TcpPorts: in.TcpPorts,
	}

	serviceResult, err := s.service.CheckVuln(ctx, vulnCheckRequest)
	if err != nil {
		return nil, err
	}

	return convertServiceResultToProto(serviceResult), nil
}

func convertServiceResultToProto(in *service.VulnCheckResponse) *pb.CheckVulnResponse {
	//checkVulnResponse := &pb.CheckVulnResponse{
	//	Results: make([]*pb.TargetResult, len(in.Results)),
	//}
	//
	//for i := 0; i < len(in.Results); i++ {
	//
	//}

	//TODO: complete

	return nil
}
