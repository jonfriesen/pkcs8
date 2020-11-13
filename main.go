package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func main() {
	fmt.Println("hello, world!")

	pub, priv, err := generateSSHKeyPair()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pub))
	fmt.Println(string(priv))

}

func generateSSHKeyPair() (publicKey []byte, privateKey []byte, err error) {
	// Generate a new private/public keypair for OpenSSH
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate ed25519 key pair")
	}
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate ssh public key")
	}

	b, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling pkcs8 pkey")
	}

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: b,
	}
	pemPrivKey := pem.EncodeToMemory(pemKey)
	authorizedKey := ssh.MarshalAuthorizedKey(sshPubKey)

	return authorizedKey, pemPrivKey, nil
}
