package configuration

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Configuration struct {
	IgnoredVulnerabilities []string `yaml:"ignored-vulnerabilities"`
}

func New(path string) (Configuration, error) {
	c := Configuration{}
	if path == "" {
		return c, nil
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = yaml.Unmarshal(contents, &c)
	return c, err
}
