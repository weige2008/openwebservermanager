package app

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type proxyRouteStatus struct {
	ListenAddress string `json:"listen_address"`
	Target        string `json:"target"`
}

type proxyListenerRoute struct {
	proxyRouteStatus
	listener net.Listener
}

func buildSequentialProxyRoutes(baseListenAddress string, targets []string) ([]proxyRouteStatus, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(baseListenAddress))
	if err != nil {
		return nil, fmt.Errorf("invalid proxy listen address: %w", err)
	}
	basePort, err := strconv.Atoi(portText)
	if err != nil || basePort <= 0 || basePort > 65535 {
		return nil, fmt.Errorf("listen port must be between 1 and 65535")
	}
	if len(targets) == 0 {
		return nil, nil
	}
	if basePort+len(targets)-1 > 65535 {
		return nil, fmt.Errorf("proxy listener range exceeds port 65535 for %d targets", len(targets))
	}
	routes := make([]proxyRouteStatus, 0, len(targets))
	for index, target := range targets {
		routes = append(routes, proxyRouteStatus{
			ListenAddress: net.JoinHostPort(host, strconv.Itoa(basePort+index)),
			Target:        strings.TrimSpace(target),
		})
	}
	return routes, nil
}

func proxyRouteStatuses(routes []proxyListenerRoute) []proxyRouteStatus {
	result := make([]proxyRouteStatus, 0, len(routes))
	for _, route := range routes {
		result = append(result, route.proxyRouteStatus)
	}
	return result
}

func proxyRoutesEqual(left []proxyListenerRoute, right []proxyRouteStatus) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ListenAddress != right[index].ListenAddress || left[index].Target != right[index].Target {
			return false
		}
	}
	return true
}
