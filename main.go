package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"

	pb "github.com/linkerTree/pb/credential"
	"google.golang.org/grpc"
)

const (
	address = "127.0.0.1:8848"
)

func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	ifc, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	return ifc
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		log.Fatal(err)
	}
	return ciphertext
}

func main() {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewUserCredentialValidatorClient(conn)
	// testing getting public key
	log.Printf("testing getting public key \n")
	r1, err := c.GetPublicKey(context.Background(), &pb.GetPublicKeyReq{})
	if err != nil {
		log.Fatalf("could not get pub: %v", err)
	}
	pub := BytesToPublicKey(r1.GetPublicKey())
	hashedPass := EncryptWithPublicKey(md5.New().Sum([]byte("enji")), pub)
	log.Printf("encrpted pass: %s\n", hashedPass)

	// testing login
	log.Printf("testing logging in \n")
	r2, err := c.ValidatePassWord(context.Background(), &pb.ValidatePassWordReq{
		UserName:          "enji",
		PassHashedWithPub: hashedPass,
	})
	if err != nil {
		log.Fatalf("could not get validate: %v", err)
	}
	log.Printf("ValidatePassWord response : %+v", r2)

	// testing isLogging in
	sessionID := r2.GetSessionID()
	r3, err := c.CheckIsLoggingIn(context.Background(), &pb.CheckIsLoggingInReq{SessionID: sessionID})
	if err != nil {
		log.Fatalf("could not call isLoggingin: %v", err)
	}
	log.Printf("CheckIsLoggingIn response : %+v", r3)

}
