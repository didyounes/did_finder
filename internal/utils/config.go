package utils

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds API keys and settings loaded from config file
type Config struct {
	VirusTotal     string `yaml:"virustotal"`
	SecurityTrails string `yaml:"securitytrails"`
	Shodan         string `yaml:"shodan"`
	Censys         string `yaml:"censys"`
	Chaos          string `yaml:"chaos"`
	PassiveTotal   string `yaml:"passivetotal"`
	GitHub         string `yaml:"github"`
	
	Resolvers []string `yaml:"resolvers"`
	
	Webhook struct {
		Discord string `yaml:"discord"`
		Slack   string `yaml:"slack"`
	} `yaml:"webhook"`
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		// Try default locations
		home, _ := os.UserHomeDir()
		candidates := []string{
			home + "/.config/did_finder/config.yaml",
			home + "/.did_finder.yaml",
			"config.yaml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	if path == "" {
		return &Config{}, nil // No config found, return empty
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	return &config, nil
}
