package peer

import (
	"fmt"
	"testing"
)

func TestAes(t *testing.T) {
	// test
	password := "gamer"
	key := KDFKeygen(password)
	plaintext := []byte("Hello, world!")
	fmt.Println("plaintext", plaintext)
	ciphertext, iv, err := AesEncrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Ciphertext:", ciphertext)
	decrypted, err := AesDecrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Decrypted:", decrypted)
	if string(plaintext) != string(decrypted) {
		t.Fatal("Decryption failed")
	}
}

func TestEncodePacket(t *testing.T) {
	// test
	m := NewMessage([]byte("Hello, world!"), []byte("IV"))
	m2 := NewMessage([]byte("Hello, world!"), []byte("IV"))
	fmt.Println("Message:", string([]byte("Hello, world!")))
	p := NewPacket([]Message{*m, *m2})
	b, err := encodePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Encoded packet:", string(b))
	p, err = decodePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Decoded packet:", string(p.Data[0].Data))
}
