package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface string `yaml:"interface"`

	Capture struct {
		Filter string `yaml:"filter"`
	} `yaml:"capture"`
}

func LoadConfig(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
