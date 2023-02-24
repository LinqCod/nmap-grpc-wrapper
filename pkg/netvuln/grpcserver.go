package netvuln

import (
	"context"
	"github.com/Ullaakut/nmap"
	api "github.com/linqcod/nmap-grpc-wrapper/pkg/api"
	log "github.com/sirupsen/logrus"
	"regexp"
	"strconv"
	"time"
)

type Server struct {
	api.UnimplementedNetVulnServiceServer
}

func (s *Server) CheckVuln(ctx context.Context, in *api.CheckVulnRequest) (*api.CheckVulnResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

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
		log.Errorf("error while creating new nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Errorf("error while running nmap scanner: %v", err)
	}

	if warnings != nil {
		log.Printf("Nmap Scanner Warnings: \n %v", warnings)
	}

	checkVulnResponse := api.CheckVulnResponse{
		Results: make([]*api.TargetResult, 0),
	}

	regex := regexp.MustCompile("(CVE-[1-9][0-9][0-9][0-9]-[1-9]*)\t(\\d.\\d)")

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		targetResult := api.TargetResult{
			Target:   host.Addresses[0].Addr,
			Services: make([]*api.Service, 0),
		}

		for _, port := range host.Ports {
			if len(port.Scripts) == 0 {
				continue
			}

			service := api.Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: int32(port.ID),
				Vulns:   make([]*api.Vulnerability, 0),
			}

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					vulnsIndexiesAndCVSSes := regex.FindAllStringSubmatch(script.Output, -1)
					for _, vulnIndexAndCVSS := range vulnsIndexiesAndCVSSes {
						cvss, err := strconv.ParseFloat(vulnIndexAndCVSS[2], 32)
						if err != nil {
							log.Errorf("error while parsing float value from string: %v", err)
						}
						service.Vulns = append(service.Vulns, &api.Vulnerability{
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
