package peer

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
)

type Profile struct {
	Name     string
	Contacts []Contact
}

func NewProfile(name string) *Profile {
	return &Profile{
		Name:     name,
		Contacts: make([]Contact, 0),
	}
}

func (p *Profile) AddContact(c *Contact) {
	p.Contacts = append(p.Contacts, *c)
}

type Contact struct {
	Name     string
	Password string
	Messages []string
}

func NewContact(name string, password string) *Contact {
	return &Contact{
		Name:     name,
		Password: password,
		Messages: make([]string, 0),
	}
}

type ProfileData struct {
	Data []byte `json:"d"`
	DIV  []byte `json:"div"`
	Hash []byte `json:"h"`
	Key  []byte `json:"k"`
	KIV  []byte `json:"kiv"`
	Salt []byte `json:"s"`
}

func NewProfileData(data []byte, div []byte, hash []byte, key []byte, kiv []byte, salt []byte) *ProfileData {
	return &ProfileData{
		Data: data,
		Hash: hash,
		Key:  key,
		KIV:  kiv,
		DIV:  div,
		Salt: salt,
	}
}

func CheckProfile() bool {
	_, err := os.Stat("profile.json")
	return !os.IsNotExist(err)
}

func SaveProfile(p *Profile, password string) error {
	salt := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}
	// random key for the profile
	kRaw := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, kRaw)
	if err != nil {
		return err
	}
	// derive master key and hash
	mk, hash := MasterKeyAndHash(salt, password)
	// convert the profile to json
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// encrypt the profile with kRaw
	data, div, _, err := AesEncrypt(b, kRaw)
	if err != nil {
		return err
	}
	// encrypt kRaw with mk
	k, kiv, _, err := AesEncrypt(kRaw, mk)
	if err != nil {
		return err
	}

	profileData := NewProfileData(data, div, hash, k, kiv, salt)
	pd, err := json.Marshal(profileData)
	if err != nil {
		return err
	}

	path := "profile.json" // Write data to filePath, create it with 0666 permissions if it does not exist
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer file.Close() // Ensure file is closed once the function returns
	// encrypt the data before writing it to the file

	// Write the data to the file
	_, err = file.Write(pd)
	if err != nil {
		return err
	}

	return nil
}

func (p *Profile) CheckContact(name string) bool {
	for _, c := range p.Contacts {
		if c.Name == name {
			return true
		}
	}
	return false
}

func LoadProfile(password string) (*Profile, error) {
	// load profile from disk
	path := "profile.json"
	// Read the entire file at once.
	pd, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profileData ProfileData
	err = json.Unmarshal(pd, &profileData)
	if err != nil {
		return nil, err
	}
	data := profileData.Data
	div := profileData.DIV
	diskHash := profileData.Hash
	k := profileData.Key
	kiv := profileData.KIV
	salt := profileData.Salt

	mk, ramHash := MasterKeyAndHash(salt, password)
	if !bytes.Equal(diskHash, ramHash) {
		return nil, errors.New("hash mismatch")
	}
	kRaw, err := AesDecrypt(k, mk, kiv, nil)
	if err != nil {
		return nil, err
	}
	b, err := AesDecrypt(data, kRaw, div, nil)
	if err != nil {
		return nil, err
	}

	var p Profile
	err = json.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}
