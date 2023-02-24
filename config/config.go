package config

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Server struct {
		Host    string `yaml:"host"`
		Port    string `yaml:"port"`
		Network string `yaml:"network"`
	} `yaml:"server"`
	Logger struct {
		Level string `yaml:"level"`
	} `yaml:"logger"`
}

func NewConfig(configPath string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("error while opening config file: %v", err)
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	if err = d.Decode(&config); err != nil {
		return nil, fmt.Errorf("error while decoding config file: %v", err)
	}

	return config, nil
}

func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("error while getting file info: %v", err)
	}

	if s.IsDir() {
		return fmt.Errorf("error. '%s' is a directory, not a file", path)
	}

	return nil
}

func ParseFlags() (string, error) {
	var configPath string

	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")
	flag.Parse()

	if err := ValidateConfigPath(configPath); err != nil {
		return "", err
	}

	return configPath, nil
}
