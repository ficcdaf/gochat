package networking

type NetworkingState struct {
	TcpServer  *TcpServer
	mdnsServer *MdnsServer
	port       int
}

func NewNetworkingState(name string, port int) *NetworkingState {
	ns := &NetworkingState{}
	ns.TcpServer = NewTcpServer(port)
	ns.mdnsServer = NewMdnsServer(name, port)
	return ns
}

func (ns *NetworkingState) Start() {
	ns.TcpServer.Start()
	ns.mdnsServer.Start()
}

func (ns *NetworkingState) Stop() {
	ns.TcpServer.Stop()
	ns.mdnsServer.Stop()
}
