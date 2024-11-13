package peer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/mdns"
	"github.com/isafic/closecircle/go-client/internal/networking"
)

// TODO: dicovered peers can be stored in a map, where the key is the host name and the value is a pointer to a PeerConnection.
// TODO: DiscoverPeers should return a map of discovered peers. There will be a separate function to connect to a peer which will add them to the map of peer connections.

func DiscoverPeers(host string) []Peer {
	// func DiscoverPeers() []Peer {
	// fmt.Println("Begin peer discovery")
	// create a channel to receive discovered peers
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	peers := make([]Peer, 0)

	go func() {
		for entry := range entriesCh {
			info := entry.InfoFields
			// skip self
			if info[0] == host {
				continue
			}
			p := NewPeer(info[0], info[1], entry.AddrV4, entry.Port)
			peers = append(peers, *p)
		}
	}()
	params := mdns.DefaultParams("_closecircle._tcp")
	// required for docker environment -- could disable later?
	params.DisableIPv6 = true
	params.Entries = entriesCh
	// mdns.Lookup("_closecircle._tcp", entriesCh)
	mdns.Query(params)
	close(entriesCh)
	// fmt.Println("End peer discovery")
	return peers
}

type Message struct {
	Data []byte
	IV   []byte
	Hash []byte
}

func NewMessage(data []byte, iv []byte, hash []byte) *Message {
	return &Message{
		Data: data,
		IV:   iv,
		Hash: hash,
	}
}

type Packet struct {
	DataList []Message
}

func NewPacket(data []Message) *Packet {
	return &Packet{
		DataList: data,
	}
}

func encodePacket(p *Packet) ([]byte, error) {
	// encode packet
	b, err := json.Marshal(p)
	if err != nil {
		fmt.Println("Error marshalling packet", err)
		return nil, err
	}
	return b, nil
}

func decodePacket(data []byte) (*Packet, error) {
	var p Packet
	err := json.Unmarshal(data, &p)
	if err != nil {
		fmt.Println("Error unmarshalling packet", err)
		return nil, err
	}
	return &p, nil
}

func VerifyIncomingConnection(conn net.Conn, password string, keyBuffer *[]byte) (bool, error) {
	fmt.Println("Verifying incoming connection")
	c1, err := receive(conn)
	if err != nil {
		return false, err
	}
	p, err := decodePacket(c1)
	if err != nil || len(p.DataList) != 1 {
		return false, err
	}
	w := KDFKeygen(password)
	privk, pubk, err := EcdhKeygen()
	if err != nil {
		return false, err
	}
	rpubkBytes, err := AesDecrypt(p.DataList[0].Data, w, p.DataList[0].IV, p.DataList[0].Hash)
	if err != nil {
		return false, err
	}
	rpubk, err := ecdh.P256().NewPublicKey(rpubkBytes)
	if err != nil {
		return false, err
	}
	// K is the shared secret
	k, err := privk.ECDH(rpubk)
	if err != nil {
		return false, err
	}

	c2, iv2, h2, err := AesEncrypt(pubk, w)
	if err != nil {
		return false, err
	}
	m2 := NewMessage(c2, iv2, h2)
	challenge, err := generateChallenge()
	if err != nil {
		return false, err
	}
	c3, iv3, h3, err := AesEncrypt(challenge, k)
	if err != nil {
		return false, err
	}
	m3 := NewMessage(c3, iv3, h3)
	p = NewPacket([]Message{*m2, *m3})
	data, err := encodePacket(p)
	if err != nil {
		return false, err
	}

	response, err := sendAndReceive(conn, data)
	if err != nil {
		return false, err
	}
	p, err = decodePacket(response)
	if err != nil || len(p.DataList) != 1 {
		return false, err
	}
	pt, err := AesDecrypt(p.DataList[0].Data, k, p.DataList[0].IV, p.DataList[0].Hash)
	if err != nil || len(p.DataList) != 1 {
		return false, err
	}
	remoteChallenge := pt[:8]
	localChallenge := pt[8:]

	if !bytes.Equal(challenge, localChallenge) {
		return false, errors.New("challenge mismatch")
	}

	c5, iv5, h5, err := AesEncrypt(remoteChallenge, k)
	if err != nil {
		return false, err
	}
	m5 := NewMessage(c5, iv5, h5)
	p = NewPacket([]Message{*m5})
	data, err = encodePacket(p)
	if err != nil {
		return false, err
	}
	err = send(conn, data)
	if err != nil {
		return false, err
	}

	copy(*keyBuffer, k)
	return true, nil
}

func VerifyOutgoingConnection(conn net.Conn, password string, keyBuffer *[]byte) (bool, error) {
	// fmt.Println("Verifying outgoing connection")
	w := KDFKeygen(password)
	privk, pubk, err := EcdhKeygen()
	if err != nil {
		return false, err
	}
	// encrypt public key with w, send to peer
	c1, iv1, h1, err := AesEncrypt(pubk, w)
	if err != nil {
		return false, err
	}
	m := NewMessage(c1, iv1, h1)
	p := NewPacket([]Message{*m})
	data, err := encodePacket(p)
	if err != nil {
		return false, err
	}

	response, err := sendAndReceive(conn, data)
	if err != nil {
		return false, err
	}
	p, err = decodePacket(response)
	if err != nil {
		return false, err
	}
	if len(p.DataList) != 2 {
		e := fmt.Sprintf("unexpected number of messages, expecting %d, got %d", 2, len(p.DataList))
		return false, errors.New(e)
	}
	// first message is the public key
	// second message is the challenge
	rpubkBytes, err := AesDecrypt(p.DataList[0].Data, w, p.DataList[0].IV, p.DataList[0].Hash)
	if err != nil {
		return false, err
	}
	rpubk, err := ecdh.P256().NewPublicKey(rpubkBytes)
	if err != nil {
		return false, err
	}
	// K is the shared secret
	k, err := privk.ECDH(rpubk)
	if err != nil {
		return false, err
	}
	rChallenge, err := AesDecrypt(p.DataList[1].Data, k, p.DataList[1].IV, p.DataList[1].Hash)
	if err != nil {
		return false, err
	}
	challenge, err := generateChallenge()
	if err != nil {
		return false, err
	}
	c4, iv4, h4, err := AesEncrypt(append(challenge, rChallenge...), k)
	if err != nil {
		return false, err
	}
	m = NewMessage(c4, iv4, h4)
	p = NewPacket([]Message{*m})
	data, err = encodePacket(p)
	if err != nil {
		return false, err
	}

	response, err = sendAndReceive(conn, data)
	if err != nil {
		return false, err
	}
	p, err = decodePacket(response)
	if err != nil {
		return false, err
	}
	if len(p.DataList) != 1 {
		e := fmt.Sprintf("unexpected number of messages, expecting %d, got %d", 1, len(p.DataList))
		return false, errors.New(e)
	}
	rChallenge, err = AesDecrypt(p.DataList[0].Data, k, p.DataList[0].IV, p.DataList[0].Hash)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(challenge, rChallenge) {
		return false, errors.New("challenge mismatch")
	}
	copy(*keyBuffer, k)
	return true, nil
}

func generateChallenge() ([]byte, error) {
	challenge := make([]byte, 8)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

func send(conn net.Conn, data []byte) error {
	// err := conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
	// if err != nil {
	// 	return err
	// }
	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func receive(conn net.Conn) ([]byte, error) {
	// err := conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	// if err != nil {
	// 	return nil, err
	// }
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func sendAndReceive(conn net.Conn, data []byte) ([]byte, error) {
	err := send(conn, data)
	if err != nil {
		return nil, err
	}
	buf, err := receive(conn)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func FindPassword(rName string, state *AppState) (string, error) {
	var password string
	for _, contact := range state.Profile.Contacts {
		if contact.Name == rName {
			password = contact.Password
			return password, nil
		}
	}
	return "", errors.New("unrecognized peer")
}

func ReceiveConnections(host string, ts *networking.TcpServer, a *AppState) {
	// this will run in a goroutine
	// assign connection to peer
	for {
		conn := <-ts.Connections
		// fmt.Println("Received connection")
		// peers := DiscoverPeers(host)
		peers := a.DiscoverAndFilter()
		if len(peers) == 0 {
			conn.Close()
			continue
		}
		var peer *Peer
		for _, p := range peers {
			if strings.Contains(conn.RemoteAddr().String(), p.Addr.String()) {
				// fmt.Println("Found peer")
				peer = &p
				break
			}
		}
		tc := networking.NewTcpConnectionFromConn(conn)
		peer.SetConnection(tc)
		k := make([]byte, 32)

		rName := peer.Name
		password, err := FindPassword(rName, a)
		if err != nil {
			fmt.Println("Error finding password: ", err)
		}

		ver, err := VerifyIncomingConnection(conn, password, &k)
		if !ver || err != nil {
			fmt.Println("Verification failed: ", err)
			break
		}
		peer.Connected = true
		peer.SessionKey = k
		// fmt.Println("Connection verified")
		a.CurrentPeer = peer
		// if not already in chat, notify the user that a peer has connected
		if !a.InChat {
			fmt.Println(a.CurrentPeer.Name, " has started a chat with you. You may open the chat from the main menu.")
		} else {
			a.MessageChan <- fmt.Sprintf("%s has entered the chat.\n", a.CurrentPeer.Name)
		}
	}
}

func ReceiveMessages(a *AppState) {
	for {
		p := a.CurrentPeer
		if p != nil {
			// fmt.Println("Receiving message")
			message, err := p.ReceiveMessage()
			// fmt.Println("this is the message: ", message)
			// If the err is io.EOF, the connection was closed by the peer.
			if err != nil {
				a.Disconnect()
				a.MessageChan <- "Peer disconnected."
				// if err == io.EOF || strings.Contains(err.Error(), "connection reset by peer") {
				// 	a.Disconnect()
				// 	a.MessageChan <- "Peer disconnected."
				// } else {
				// 	fmt.Println("Error receiving message: ", err)
				// }
			} else {
				message = fmt.Sprintf("%s: %s", p.Name, message)
				a.MessageChan <- message
			}
		}

	}
}
