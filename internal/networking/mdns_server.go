package networking

import (
	"github.com/hashicorp/mdns"
)

type MdnsServer struct {
	server *mdns.Server
	Name   string
	PubKey string
	Port   int
}

func NewMdnsServer(host string, port int) *MdnsServer {
	return &MdnsServer{
		Port:   port,
		Name:   host,
		PubKey: "TODO",
	}
}

func (s *MdnsServer) Start() error {
	// Setup our service export
	host := s.Name
	info := []string{s.Name, s.PubKey}
	service, _ := mdns.NewMDNSService(host, "_closecircle._tcp", "", "", s.Port, nil, info)

	// Create the mDNS server, defer shutdown
	server, err := mdns.NewServer(&mdns.Config{Zone: service, LogEmptyResponses: false})
	if err != nil {
		return err
	}
	s.server = server
	return nil
}

func (s *MdnsServer) Stop() {
	if s.server != nil {
		s.server.Shutdown()
	}
}
