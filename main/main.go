package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/chentanyi/cloudflare-worker-proxy/cert"
	"github.com/chentanyi/cloudflare-worker-proxy/proxy"
	"github.com/sirupsen/logrus"
)

type Config struct {
	LogLevel  string `json:"log"`
	LogCaller bool   `json:"logCaller"`
	Addr      string `json:"addr"`
	Target    string `json:"target"`
	Password  string `json:"password"`
	CAFile    string `json:"caFile"`
	CertFile  string `json:"certFile"`
}

func fixupFilepath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("unable to get home dir: %v", err)
		}
		path = filepath.Join(home, path[1:])
	}
	return path, nil
}

func main() {
	configBytes, err := ioutil.ReadFile("config.json")
	if err != nil {
		logrus.SetReportCaller(true)
		logrus.Errorf("ioutil.ReadFile: %v", err)
		return
	}
	config := &Config{}
	err = json.Unmarshal(configBytes, config)
	if err != nil {
		logrus.SetReportCaller(true)
		logrus.Errorf("json.Unmarshal: %v", err)
		return
	}
	if config.LogCaller {
		logrus.SetReportCaller(true)
	}
	if loglevel, err := logrus.ParseLevel(config.LogLevel); err != nil {
		logrus.Warnf("logrus.ParseLevel: %v", err)
	} else {
		logrus.SetLevel(loglevel)
	}

	cafile, err := fixupFilepath(config.CAFile)
	if err != nil {
		logrus.Error("CAFile: %v", err)
		return
	}
	ca, err := cert.NewCA(cafile)
	if err != nil {
		logrus.Errorf("NewCA: %v", err)
		return
	}
	cert, err := fixupFilepath(config.CertFile)
	if err != nil {
		logrus.Error("CertFile: %v", err)
		return
	}
	if cert != "" {
		err = ca.ExportCertToFile(cert)
		if err != nil {
			logrus.Errorf("ca.ExportCertToFile: %v", err)
			return
		}
	}

	options := &proxy.Options{
		Target:    config.Target,
		Password:  config.Password,
		CA:        ca,
		TCPListen: func() (net.Listener, error) { return net.Listen("tcp", config.Addr) },
	}
	server := proxy.NewServer(options)
	for err = range server.Start() {
		logrus.Errorf("server.Start: %v", err)
		return
	}
}
