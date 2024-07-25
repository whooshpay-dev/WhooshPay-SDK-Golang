package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

type Data struct {
	Message string `json:"grantType"`
}

func accessToken() {
	fmt.Println("=====> step2 : Create Access Token. You need set your timestamp|clientKey|privateKey")

	//get time
	timestamp := "2023-11-21T11:03:47+07:00"
	//get merchantId from merchant platform
	clientKey := "sandbox-10004"
	//build string to sign
	stringToSign := clientKey + "|" + timestamp
	fmt.Println(stringToSign)

	//signature
	signatureBase64, done := signature(stringToSign)
	if done {
		return
	}

	//postJson
	postJson(timestamp, clientKey, signatureBase64)
}

// signature
func signature(stringToSign string) (string, bool) {
	// get from step1;  Base64-encoded private key
	privateKeyBase64 := "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDGWPgn9MHGpINP55SCJnBIoti5GU4/50ijdvna6ErZLpwLb0CYIlUaXS6YYv2GMW8SXyT2CaVb53tlS7Y6tSzgVNvGB07wJJkkq66ZLlXEkpsXu4lXOgz1D+jxubrdofbVNj5RK3PC/JQjL4brueuBuXyGSWBfSviCy2DximOPh/yCwslK6Fa8JPwehoBFHzECSOmZkPxg1F7VMxKH6EF/qSt5/KAe9fFwe1Nu6ro5pciFK6gEBTuO+p6fnvUEDepW83Ca0hsTqil7Uy1Ule1soQuQH0RWab6MBRqcfeuk82qDnmCaEAZ+PMdX51vxKMvJgtk7un2vBA4yt7hfJ1PbAgMBAAECggEAEnjjt5joWQ8mOZFYN9zLlUAxTd/I9VOdZLfmYhhDLEHWf4wfaGu+IEPwXHnPoalF7mCVCSLx1wLSb6ci9Am+ga/1fdZdaCkIaC1jB9oUW8fJkObCzjBWV5ZhO+3vtMdqPQYdvKJ+1/h89V/uQVLh14WGTt1Tj9xkE45MW4JnbkzyS3CNrzSIlBl0w1PEyPHoqv4wOZjSinedMsKE0IAXhgOu4hClebkeX+0eBvkVNi17+KHK+Aizf2DwJ6+RUUCeGr7yKdOOBxZxkEEEKwHNRkjG0MH69s3Vs80w2NSM89xYqX8No5dwMC0Hhp/i87k2o/qM+J0BuLI9uee9KpXqUQKBgQDS6VbTXF4O2g88OKvH//4CSsG6N8ySAHmJJfNha4u7kmCQz9iLNblRI4Aoei4KIVdY/kHorSijMSa025ki8ebQLw7G5Me5nqBOiuRqlIbXfTaCxjWggzm434mPs/2998GGPEIm1g+qBML2gv42XqG391hrOFpx0EaozmR6JBT+8QKBgQDwwAlo+JOPLlCvfHiMEu+/bMU7F9HKJDOsgG5fFxScUfBBVhXslpV6h23iXp4v/VmF+5EeCIE4gInXEyj9Yn9gpaL72Gdf8PXyZel9WrRfL3CyH0vnR1DM60FHAFmEFUkFvCmzDyOqZmyt2DpYcd4y9Kfs/Ts/iRfvAFAtoO1XiwKBgE59IZ+0nxg91C+gE2VxgdDOizvGqi2nWZNNeT5G7JBYT/F0N+zOiHGGmZn2pg2FDOGEdXimgBoDH5lso5eamD/fU0t3NlCAlL3F+G0lauzknxWZt7lNPHztS18cJ5C7k9xlrmSPgvLNpNRiOUJ4gwxYUyJLrXTvgmwtqry9ksaxAoGAFkiQFmk7rzsIONX6imyOSFeXAds4jc9AAS16Cc8nFzj2VfXT3awqdcbnQtajKan3iVE5o2ACJeqv13pshteBFr7+EPV8zAKPoToRnIqyu0S216XR7rxJHE6CIkJEBte5hJBgA7TZBkKouIaVD+6qNGk0ydi+jSjxUCvlP/PvQ/UCgYBa/ANDflVEvas7txSmqJJ4mDyExs3lcQ2dEBVj6cbfEGDJH0QiOJwbnTAKnub7nNJEWIzIjmNBLoZBUQ1Ox8rRYqvLs0Edl99Y3CFx4boRuBB690kFABl3XzAwpWX266vZfRCg8BcGqpH/BTuAvSW4gHKCGhyqGlDes8w9OUq+4A=="

	// Decode the base64 string to obtain the PEM encoded bytes
	pemBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		fmt.Println("Error decoding private key:", err)
		return "", true
	}

	// Parse the DER encoded bytes to obtain the private key
	privateKey, err := x509.ParsePKCS8PrivateKey(pemBytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return "", true
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Println("Invalid private key type")
		return "", true
	}

	// Data to be signed
	message := []byte(stringToSign)

	// Compute the SHA-256 hash of the data
	hashed := sha256.Sum256(message)

	// Sign the hashed message using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing the message:", err)
		return "", true
	}

	// Convert the signature to base64 string
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Display the base64-encoded signature
	fmt.Println("Base64-encoded Signature:")
	fmt.Println(signatureBase64)
	return signatureBase64, false
}

func postJson(timestamp string, clientKey string, signatureBase64 string) {
	// Create the JSON payload
	data := Data{
		Message: "client_credentials",
	}

	jsonPayload, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// Send the POST request
	url := "https://sandbox-gateway-test.whooshpay.id/v1.0/access-token/b2b"
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Add custom headers
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-TIMESTAMP", timestamp)
	request.Header.Add("X-CLIENT-KEY", clientKey)
	request.Header.Add("X-SIGNATURE", signatureBase64)

	// Send the request
	client := http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer response.Body.Close()

	// Check the response status code
	if response.StatusCode != http.StatusOK {
		fmt.Println("Request failed with status code:", response.StatusCode)
		return
	}

	// Read the response body
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	// Process the response
	fmt.Println("Response:")
	fmt.Println(result)
}
