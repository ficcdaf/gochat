package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/isafic/closecircle/go-client/internal/peer"
	"github.com/manifoldco/promptui"
	"github.com/rivo/tview"
)

func main() {
	log.Default().SetOutput(io.Discard)
	uimain()
}

func uimain() {
	// check if profile exists
	profile, password, err := initProfile()
	if err != nil {
		fmt.Println("Error initializing profile: ", err)
		return
	}
	a := peer.NewAppState(profile, password)
	a.Start()
	menu(a)
}

// TODO:
// - Add a function to send files DONE
// - Add a function to receive files DONE
// - Encrypt profile data
// - Save messages to contact data DONE
// - Verification with hash DONE

func menu(a *peer.AppState) {
	profile := a.Profile
	for {
		prompt := promptui.Select{
			Label: "Select an option:",
			Items: []string{
				"Register A Contact", "Connect to a Contact", "Enter Chat", "View Messages", "Exit",
			},
		}

		_, s, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}
		switch s {
		case "Register A Contact":
			name, err := promptUser("Enter the name of the contact", false)
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				continue
			}
			if profile.CheckContact(name) {
				fmt.Println("Contact already exists.")
				continue
			}
			password, err := promptUser("Enter the shared password", true)
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				continue
			}
			c := peer.NewContact(name, password)
			profile.AddContact(c)
			fmt.Println("Contact added.")

		case "Connect to a Contact":
			peers := a.DiscoverAndFilter()
			if len(peers) == 0 {
				fmt.Println("No contacts are online.")
				continue
			}
			names := getNames(peers)
			selection, err := promptSelect("Select from available contacts", names)
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				continue
			}
			p, err := getPeer(selection, peers)
			if err != nil {
				fmt.Printf("Internal error %v\n", err)
				continue
			}

			password, err := peer.FindPassword(selection, a)
			if err != nil {
				fmt.Println("Error getting stored password: ", err)
			}
			fmt.Println("Initiating connection to ", selection)
			err = p.Connect(password)
			if err != nil {
				fmt.Println("Error connecting to peer: ", err)
			}
			a.CurrentPeer = &p
			fmt.Println("Connection established and verified. You may enter the chat.")
		case "Enter Chat":
			chat(a)
		case "View Messages":
			viewMessages(a)
		default:
			// save profile
			peer.SaveProfile(profile, a.Password)
			fmt.Printf("%v\n", a.Profile)
			return
		}
	}
}

func viewMessages(a *peer.AppState) {
	contacts := a.Profile.Contacts
	names := getContactNames(contacts)
	selection, err := promptSelect("Select from available contacts", names)
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	for _, c := range contacts {
		if c.Name == selection {
			for _, m := range c.Messages {
				fmt.Println(m)
			}
		}
	}
	promptUser("Press enter to continue", false)
}

func chat(a *peer.AppState) {
	a.InChat = true
	welcome := "Welcome to the chat. Type :q to exit to the menu. Your chat will remain active.\nUse :file [filename.ext] to send a file. Only files in the same folder as the executable are supported.\n"
	app := tview.NewApplication()

	// Create the views for the messages and the input field.
	messagesView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	messagesView.Write([]byte(welcome))

	inputField := tview.NewInputField().
		SetLabel("Enter message: ").
		SetFieldWidth(0)

	inputField.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			// Handle the entered message.
			message := inputField.GetText()
			if message == ":q" {
				app.Stop()
			} else {

				if message != "" {
					var isFile bool
					if len(message) < 6 {
						isFile = false
					} else {
						isFile = message[:6] == ":file "
					}
					if isFile {
						path := message[6:]
						messagesView.Write([]byte("You sent a file: " + path + "\n"))
						// Call your function for sending the message to the other peer here.
						a.SendMessage(path, true)
						a.SaveMessage("You sent a file: " + path + "\n")
					} else {

						messagesView.Write([]byte("You: " + message + "\n"))
						// Call your function for sending the message to the other peer here.
						a.SendMessage(message, false)
						a.SaveMessage("You: " + message + "\n")
					}

				}

				inputField.SetText("")
			}
		}
	})

	// Create a flex layout and add the views to it.
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(messagesView, 0, 1, false).
		AddItem(inputField, 1, 1, true)

	var buffer bytes.Buffer

	// Start a goroutine to listen for incoming messages and update the messagesView.
	go func() {
		for message := range a.MessageChan {
			// fmt.Println("Attempting to write message to view.")
			buffer.WriteString(message + "\n")
			app.QueueUpdateDraw(func() {
				messagesView.Write([]byte(message + "\n"))
				a.SaveMessage(message)
			})
		}
	}()

	// Start the application.
	if err := app.SetRoot(flex, true).Run(); err != nil {
		panic(err)
	}
	a.Disconnect()
	a.InChat = false
}

func getPeer(name string, peers []peer.Peer) (peer.Peer, error) {
	for _, p := range peers {
		if p.Name == name {
			return p, nil
		}
	}
	return peer.Peer{}, errors.New("peer not found")
}

func getNames(peers []peer.Peer) []string {
	names := make([]string, 0)
	for _, p := range peers {
		names = append(names, p.Name)
	}
	return names
}

func getContactNames(contacts []peer.Contact) []string {
	names := make([]string, 0)
	for _, p := range contacts {
		names = append(names, p.Name)
	}
	return names
}

func promptSelect(s string, items []string) (string, error) {
	prompt := promptui.Select{
		Label: s,
		Items: items,
	}

	_, res, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return res, nil
}

func promptUser(s string, password bool) (string, error) {
	var prompt promptui.Prompt
	if password {
		prompt = promptui.Prompt{
			Label:    s,
			Validate: validatePassword,
			Mask:     '*',
		}
	} else {
		prompt = promptui.Prompt{
			Label: s,
		}
	}
	result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return result, nil
}

func initProfile() (*peer.Profile, string, error) {
	for {
		if peer.CheckProfile() {
			password, err := promptUser("Enter your password", true)
			if err != nil {
				fmt.Println("Error loading profile: ", err)
				fmt.Println("Exiting program.")
				return nil, "", err
			}
			profile, err := peer.LoadProfile(password)
			if err != nil {
				fmt.Println("Error loading profile: ", err)
				fmt.Println("Exiting program.")
				return nil, "", err
			}
			return profile, password, nil
		} else {
			// create new profile
			fmt.Println("There are no saved profiles. Please create a new profile.")
			// prompt user for username and password
			prompt := promptui.Prompt{
				Label: "Username",
			}
			username, err := prompt.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				continue
			}
			fmt.Printf("Welcome, %s. Please enter a secure password.\nThere is no recovery option, so choose something memorable.", username)
			prompt = promptui.Prompt{
				Label:    "Password",
				Validate: validatePassword,
				Mask:     '*',
			}

			password, err := prompt.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				continue
			}
			profile := peer.NewProfile(username)
			peer.SaveProfile(profile, password)
			return profile, password, nil
		}
	}
}

func validatePassword(input string) error {
	// if password is valid, return nil
	if len(input) < 4 {
		return errors.New("password must have more than 6 characters")
	}
	return nil // else return error
}

func testmain() {
	// Host name will just be username
	host := os.Getenv("PEER_NAME")
	p := peer.NewProfile(host)
	p.AddContact(peer.NewContact("bob", "gamer"))
	p.AddContact(peer.NewContact("alice", "gamer"))
	a := peer.NewAppState(p, "gamer")
	a.Start()

	time.Sleep(1 * time.Second)
	if host == "alice" {
		a.DiscoverAndConnect()
		time.Sleep(1 * time.Second)
		fmt.Println("Alice sending message to Bob")
		a.SendMessage("Hello from Alice", false)
	}
	for {
		time.Sleep(1 * time.Second)
	}
	// time.Sleep(5 * time.Second)
	// s.Stop()
	// fmt.Println("Server stopped, exiting program.")
}
