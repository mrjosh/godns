package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ConfMap struct {
	Dns      []string     `yaml:"dns"`
	RouterOS RouterOSConf `yaml:"routeros"`
}

type RouterOSConf struct {
	Address  string  `yaml:"address"`
	UseTLS   bool    `yaml:"usetls"`
	Port     int32   `yaml:"port"`
	Username string  `yaml:"username"`
	Password string  `yaml:"password"`
	VPN      VPNConf `yaml:"vpn"`
}

type VPNConf struct {
	Interface          string   `yaml:"interface"`
	WhitelistedDomains []string `yaml:"whitelisted_domains"`
}

func Load(filename string) (*ConfMap, error) {

	cf, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	confMap := new(ConfMap)
	if err := yaml.NewDecoder(cf).Decode(confMap); err != nil {
		return nil, err
	}

	return confMap, nil
}
