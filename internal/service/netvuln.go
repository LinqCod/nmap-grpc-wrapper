package service

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap"
	"regexp"
	"strconv"
	"time"
)

type (
	VulnCheckRequest struct {
		Targets  []string
		TcpPorts []int32
	}

	VulnCheckResponse struct {
		Results []*TargetResult
	}

	TargetResult struct {
		Target   string
		Services []*Service
	}

	Service struct {
		Name    string
		Version string
		TcpPort int32
		Vulns   []*Vulnerability
	}

	Vulnerability struct {
		Identifier string
		CvssScore  float32
	}
)

type VulnChecker interface {
	CheckVuln(ctx context.Context, request *VulnCheckRequest) (*VulnCheckResponse, error)
}

type VulnCheckerService struct{}

func New() VulnChecker {
	return &VulnCheckerService{}
}

func (v *VulnCheckerService) CheckVuln(ctx context.Context, request *VulnCheckRequest) (*VulnCheckResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	scannerOpts := []func(*nmap.Scanner){
		nmap.WithContext(ctx),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
	}

	if len(request.Targets) != 0 {
		scannerOpts = append(scannerOpts, nmap.WithTargets(request.Targets...))
	}
	if len(request.TcpPorts) != 0 {
		ports := make([]string, len(request.TcpPorts))
		for i := 0; i < len(request.TcpPorts); i++ {
			ports[i] = strconv.Itoa(int(request.TcpPorts[i]))
		}

		scannerOpts = append(scannerOpts, nmap.WithPorts(ports...))
	}

	scanner, err := nmap.NewScanner(scannerOpts...)
	if err != nil {
		return nil, fmt.Errorf("error while creating new nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("error while running nmap scanner: %v", err)
	}

	if warnings != nil {
		return nil, fmt.Errorf("Nmap Scanner Warnings: \n %v", warnings)
	}

	vulnCheckResponse := VulnCheckResponse{
		Results: make([]*TargetResult, 0),
	}

	regex := regexp.MustCompile("(CVE-[1-9][0-9][0-9][0-9]-[1-9]*)\t(\\d.\\d)")

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		targetResult := TargetResult{
			Target:   host.Addresses[0].Addr,
			Services: make([]*Service, 0),
		}

		for _, port := range host.Ports {
			if len(port.Scripts) == 0 {
				continue
			}

			service := Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: int32(port.ID),
				Vulns:   make([]*Vulnerability, 0),
			}

			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					vulnsIndexiesAndCVSSes := regex.FindAllStringSubmatch(script.Output, -1)
					for _, vulnIndexAndCVSS := range vulnsIndexiesAndCVSSes {
						cvss, err := strconv.ParseFloat(vulnIndexAndCVSS[2], 32)
						if err != nil {
							return nil, fmt.Errorf("error while parsing float value from string: %v", err)
						}
						service.Vulns = append(service.Vulns, &Vulnerability{
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
			vulnCheckResponse.Results = append(vulnCheckResponse.Results, &targetResult)
		}
	}

	return &vulnCheckResponse, nil
}
