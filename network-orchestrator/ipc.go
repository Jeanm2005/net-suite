package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type scanRequest struct {
	Target      string `json:"target"`
	StartPort   int    `json:"start_port"`
	EndPort     int    `json:"end_port"`
	Concurrency int    `json:"concurrency"`
}

type openPort struct {
	Port	int	`json:"port"`
	Banner	*string	`json:"banner"`
}

type scanResponse struct {
	Target    string     `json:"target"`
	OpenPorts []openPort `json:"open_ports"`
	Error     *string    `json:"error"`	
}

func scanViaDaemon(socketPath, target string, startPort, endPort int) (*scanResponse, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to scanner daemon: %w", err)
	}
	defer conn.Close()

	req := scanRequest{Target: target, StartPort: startPort, EndPort: endPort, Concurrency: 200}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(body); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp scanResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("bad response %q: %w", string(respBytes), err)
	}
	return &resp, nil
}
