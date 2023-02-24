package netvuln

import (
	"context"
	"github.com/Ullaakut/nmap"
	"log"
	"regexp"
	"strconv"
	"time"
)

type Server struct {
	grpc.UnimplementedNetVulnServiceServer
}

func (s *Server) CheckVuln(ctx context.Context, in *grpc.CheckVulnRequest) (*grpc.CheckVulnResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ports := make([]string, 0)
	for _, port := range in.TcpPorts {
		ports = append(ports, strconv.Itoa(int(port)))
	}

	scannerOpts := []func(*nmap.Scanner){
		nmap.WithContext(ctx),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	}

	if len(in.Targets) != 0 {
		scannerOpts = append(scannerOpts, nmap.WithTargets(in.Targets...))
	}
	if len(in.TcpPorts) != 0 {
		ports := make([]string, len(in.TcpPorts))
		for i := 0; i < len(in.TcpPorts); i++ {
			ports[i] = strconv.Itoa(int(in.TcpPorts[i]))
		}

		scannerOpts = append(scannerOpts, nmap.WithPorts(ports...))
	}

	scanner, err := nmap.NewScanner(scannerOpts...)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}

	checkVulnResponse := grpc.CheckVulnResponse{
		Results: make([]*grpc.TargetResult, 0),
	}

	regex := regexp.MustCompile("(OSV:CVE-[1-9][0-9][0-9][0-9]-[1-9]*)\t(\\d.\\d)")

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		targetResult := grpc.TargetResult{
			Target:   host.Addresses[0].Addr,
			Services: make([]*grpc.Service, 0),
		}

		for _, port := range host.Ports {
			if len(port.Scripts) == 0 {
				continue
			}

			service := grpc.Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: int32(port.ID),
				Vulns:   make([]*grpc.Vulnerability, 0),
			}

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					vulnsIndexiesAndCVSSes := regex.FindAllStringSubmatch(script.Output, -1)
					for _, vulnIndexAndCVSS := range vulnsIndexiesAndCVSSes {
						cvss, err := strconv.ParseFloat(vulnIndexAndCVSS[2], 32)
						if err != nil {
							log.Fatal(err)
						}
						service.Vulns = append(service.Vulns, &grpc.Vulnerability{
							Identifier: vulnIndexAndCVSS[1],
							CvssScore:  float32(cvss),
						})
					}
				}
			}
			if len(service.Vulns) > 0 {
				targetResult.Services = append(targetResult.Services, &service)
			}
		}
		if len(targetResult.Services) > 0 {
			checkVulnResponse.Results = append(checkVulnResponse.Results, &targetResult)
		}
	}

	return &checkVulnResponse, nil
}
