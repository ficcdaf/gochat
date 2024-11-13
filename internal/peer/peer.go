package peer

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/isafic/closecircle/go-client/internal/networking"
)

type Peer struct {
	Connection *networking.TcpConnection
	Name       string
	PubKey     string
	Addr       net.IP
	SessionKey []byte
	Port       int
	Connected  bool
}

func NewPeer(name string, pubKey string, addr net.IP, port int) *Peer {
	return &Peer{
		Name:      name,
		PubKey:    pubKey,
		Addr:      addr,
		Port:      port,
		Connected: false,
	}
}

func (p *Peer) SetConnection(conn *networking.TcpConnection) {
	p.Connection = conn
}

func (p *Peer) Connect(password string) error {
	p.Connection = networking.NewTcpConnection(p.Addr.String(), p.Port)
	p.Connection.Connect()
	k := make([]byte, 32)
	ver, err := VerifyOutgoingConnection(p.Connection.Conn, password, &k)
	if !ver || err != nil {
		p.Close()
		fmt.Println("Verification failed: ", err)
		return errors.New("Verification failed")
	}
	p.Connected = true
	p.SessionKey = k
	// fmt.Println("Connection verified")
	return nil
	// Key agreement here
}

func (p *Peer) Close() {
	p.Connection.Close()
}

func (p *Peer) SendMessage(message string, isFile bool) error {
	// fmt.Println("Sending messag in peer")
	if !isFile {

		c1, iv1, hash, err := AesEncrypt([]byte(message), p.SessionKey)
		if err != nil {
			return err
		}
		m := NewMessage(c1, iv1, hash)
		pak := NewPacket([]Message{*m})
		data, err := encodePacket(pak)
		if err != nil {
			return err
		}
		err = send(p.Connection.Conn, data)
		if err != nil {
			return err
		}
	} else {
		// message is file path
		b, err := os.ReadFile(message)
		if err != nil {
			return err
		}
		c1, iv1, hash, err := AesEncrypt(b, p.SessionKey)
		if err != nil {
			return err
		}
		c2, iv2, hash2, err := AesEncrypt([]byte(message), p.SessionKey)
		if err != nil {
			return err
		}
		m1 := NewMessage(c1, iv1, hash)
		m2 := NewMessage(c2, iv2, hash2)
		pak := NewPacket([]Message{*m1, *m2})
		data, err := encodePacket(pak)
		if err != nil {
			return err
		}
		err = send(p.Connection.Conn, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Peer) ReceiveMessage() (string, error) {
	// fmt.Println("Receiving message in peer")
	buf, err := receive(p.Connection.Conn)
	if err != nil {
		return "", err
	}
	pak, err := decodePacket(buf)
	if err != nil {
		return "", err
	}
	// fmt.Println("Received packet", pak)
	// TODO: check if a file is being sent
	if len(pak.DataList) == 2 {
		// file is being sent

		m1 := pak.DataList[0]
		data, err := AesDecrypt(m1.Data, p.SessionKey, m1.IV, m1.Hash)
		if err != nil {
			return "", err
		}
		m2 := pak.DataList[1]
		path, err := AesDecrypt(m2.Data, p.SessionKey, m2.IV, m2.Hash)
		if err != nil {
			return "", err
		}

		file, err := os.OpenFile(string(path), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return "", err
		}
		defer file.Close() // Ensure file is closed once the function returns
		// encrypt the data before writing it to the file

		// Write the data to the file
		_, err = file.Write(data)
		if err != nil {
			return "", err
		}
		return "File received: " + string(path), nil
	} else {
		m := pak.DataList[0]
		dec, err := AesDecrypt(m.Data, p.SessionKey, m.IV, m.Hash)
		if err != nil {
			return "", err
		}
		return string(dec), nil
	}
}
