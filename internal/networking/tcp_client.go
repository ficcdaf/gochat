package networking

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
)

type TcpConnection struct {
	Conn            net.Conn
	inMessageQueue  chan []byte
	outMessageQueue chan []byte
	address         string
}

func (c *TcpConnection) GetConnection() *net.Conn {
	return &c.Conn
}

func NewTcpConnection(address string, port int) *TcpConnection {
	return &TcpConnection{
		address:         address + fmt.Sprintf(":%d", port),
		inMessageQueue:  make(chan []byte),
		outMessageQueue: make(chan []byte),
	}
}

func NewTcpConnectionFromConn(conn net.Conn) *TcpConnection {
	address := conn.RemoteAddr().String()
	host, portS, _ := net.SplitHostPort(address)
	port, err := strconv.Atoi(portS)
	if err != nil {
		fmt.Println("Error converting port to int", err)
		return nil
	}
	tc := NewTcpConnection(host, port)
	tc.Conn = conn
	return tc
}

func (c *TcpConnection) Connect() {
	conn, err := net.Dial("tcp", c.address)
	c.Conn = conn
	if err != nil {
		fmt.Printf("Error connecting to server at %s: %v\n", c.address, err)
		return
	}

	fmt.Println("Connected to the server.")
}

func (c *TcpConnection) Send(message string) {
	fmt.Fprint(c.Conn, message)
	// Reading the response
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println("Error reading response from server:", err)
		return
	}

	fmt.Printf("Received response: %s", response)
}

func (c *TcpConnection) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}
