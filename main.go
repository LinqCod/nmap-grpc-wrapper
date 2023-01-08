package main

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap"
	"log"
	"strconv"
	"time"
)

type CheckVulnResponse struct {
	Results []TargetResult
}

type TargetResult struct {
	Target   string
	Services []Service
}

type Service struct {
	Name    string
	Version string
	TCPPort int32
	Vulns   []Vulnerability
}

type Vulnerability struct {
	Identifier string
	CVSSScore  float32
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets("facebook.com", "google.com"),
		nmap.WithContext(ctx),
		nmap.WithServiceInfo(),
		nmap.WithScripts("vulners"),
		//nmap.WithScriptArguments(map[string]string{"mincvss": "5.0"}),
	)
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

	checkVulnResponse := CheckVulnResponse{
		Results: make([]TargetResult, 0),
	}

	// Parse nmap vulners results
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		targetResult := TargetResult{
			Target:   host.Addresses[0].Addr,
			Services: make([]Service, 0),
		}

		for _, port := range host.Ports {
			if len(port.Scripts) == 0 {
				continue
			}

			service := Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TCPPort: int32(port.ID),
				Vulns:   make([]Vulnerability, 0),
			}
			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					for _, t := range script.Tables {
						for _, table := range t.Tables {
							var vuln Vulnerability
							for _, elem := range table.Elements {
								switch elem.Key {
								case "id":
									vuln.Identifier = elem.Value
								case "cvss":
									cvss, err := strconv.ParseFloat(elem.Value, 32)
									if err != nil {
										log.Fatal(err)
									}
									vuln.CVSSScore = float32(cvss)
								}
							}
							if vuln.Identifier != "" {
								service.Vulns = append(service.Vulns, vuln)
							}
						}
					}
				}
			}
			if len(service.Vulns) > 0 {
				targetResult.Services = append(targetResult.Services, service)
			}
		}
		if len(targetResult.Services) > 0 {
			checkVulnResponse.Results = append(checkVulnResponse.Results, targetResult)
		}
	}

	fmt.Println(checkVulnResponse)
	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
