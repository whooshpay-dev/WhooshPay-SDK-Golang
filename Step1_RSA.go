package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func generateRSA() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA key:", err)
		return
	}

	// Encode private key to DER format (PKCS#8)
	privateKeyDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)

	// Encode public key to DER format (X.509)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("Error encoding public key:", err)
		return
	}

	// Convert private key DER to base64 string
	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKeyDER)
	fmt.Println("Base64-encoded private key:")
	fmt.Println(privateKeyBase64)
	fmt.Println(len(privateKeyBase64))

	// Convert public key DER to base64 string
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyDER)
	fmt.Println("Base64-encoded public key:")
	fmt.Println(publicKeyBase64)
	fmt.Println(len(publicKeyBase64))
	fmt.Println("=====> Please note this set of [RSA Key Pair] and send the [public key] to WhooshPay. so that WhooshPay can verify the request")
}
