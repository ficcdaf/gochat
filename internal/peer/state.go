package peer

import (
	"fmt"

	"github.com/isafic/closecircle/go-client/internal/networking"
)

type AppState struct {
	CurrentPeer        *Peer
	CurrentPeerChanged chan bool
	NetworkState       *networking.NetworkingState
	Profile            *Profile
	MessageChan        chan string
	InChat             bool
	Password           string
}

func NewAppState(p *Profile, password string) *AppState {
	return &AppState{
		Profile:            p,
		NetworkState:       networking.NewNetworkingState(p.Name, 8080),
		CurrentPeerChanged: make(chan bool),
		MessageChan:        make(chan string),
		InChat:             false,
		Password:           password,
	}
}

func (a *AppState) Start() {
	a.NetworkState.Start()
	go ReceiveConnections(a.Profile.Name, a.NetworkState.TcpServer, a)
	go ReceiveMessages(a)
	// go DisplayMessages(a)
}

func (a *AppState) SaveMessage(message string) {
	if a.CurrentPeer == nil {
		return
	}
	for i, contact := range a.Profile.Contacts {
		if contact.Name == a.CurrentPeer.Name {
			a.Profile.Contacts[i].Messages = append(contact.Messages, message)
		}
	}
}

func DisplayMessages(a *AppState) {
	for {
		message := <-a.MessageChan
		if !a.InChat {
			message = ""
			continue
		}
		fmt.Println(message)
		// message = ""
	}
}

func (a *AppState) DiscoverAndFilter() []Peer {
	peers := DiscoverPeers(a.Profile.Name)
	contacts := a.Profile.Contacts
	contactPeers := make([]Peer, 0)
	for _, p := range peers {
		for _, c := range contacts {
			if p.Name == c.Name {
				contactPeers = append(contactPeers, p)
			}
		}
	}
	return contactPeers
}

func (a *AppState) DiscoverAndConnect() {
	peers := DiscoverPeers(a.Profile.Name)
	selection := "bob"
	password, err := FindPassword(selection, a)
	if err != nil {
		fmt.Println("Error connecting to peer: ", err)
	}
	// TODO: prompt user to select peer
	// for now, just connect to first peer
	for _, p := range peers {
		err := p.Connect(password)
		if err != nil {
			fmt.Println("Error connecting to peer: ", err)
		}
		a.CurrentPeer = &p
	}
}

func (a *AppState) SendMessage(message string, isFile bool) {
	// fmt.Println("Sending message in app state")
	if a.CurrentPeer != nil {
		// fmt.Println("Current peer is not nil")
		err := a.CurrentPeer.SendMessage(message, isFile)
		if err != nil {
			fmt.Println("Error sending message: ", err)
		}
	}
}

func (a *AppState) Stop() {
	a.NetworkState.Stop()
}

func (a *AppState) Disconnect() {
	a.CurrentPeer = nil
}
