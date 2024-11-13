package networking

import (
	"fmt"
	"net"
)

type TcpServer struct {
	listener    net.Listener
	stopChan    chan struct{}
	Connections chan net.Conn
	port        int
}

func NewTcpServer(port int) *TcpServer {
	return &TcpServer{
		port:        port,
		stopChan:    make(chan struct{}),
		Connections: make(chan net.Conn),
	}
}

func (s *TcpServer) handleConnection(conn net.Conn) {
	// handle incoming connection
	// defer conn.Close()
	// Verify the connection
	// If verified, add this connection to the appropriate peer's struct
	// Ensuring that there is only one connection per peer
	// fmt.Println("Connection from", conn.RemoteAddr())
	// for incoming messages, add them to a channel
	// the channel will be read by the main process which will decrypt them
	// once decrypted they will be added to the appropriate peer's message history
	//

	// defer conn.Close()
	s.Connections <- conn

	// buf := make([]byte, 1024)
	// for {
	// 	n, err := conn.Read(buf)
	// 	if err != nil {
	// 		if err != io.EOF {
	// 			fmt.Println("read error:", err)
	// 		}
	// 		break
	// 	}
	// 	fmt.Println("received data:", string(buf[:n]))
	// }
}

func (s *TcpServer) Start() {
	var err error
	// Create listener
	s.listener, err = net.Listen("tcp", "0.0.0.0:"+fmt.Sprintf("%d", s.port))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	go func() {
		for {
			// Wait for incoming connection
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				// Check if the server was stopped
				case <-s.stopChan:
					fmt.Println("Server stopped")
					return

				default:
					// Error with the connection but server not stopped
					fmt.Println("Error accepting:", err)
				}
				continue
			}
			go s.handleConnection(conn)
		}
	}()
}

func (s *TcpServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	close(s.stopChan)
}
