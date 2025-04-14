package main

import (
	"fmt"
	"github.com/hasmanytrees/jwt-verifier/jwt"
	"log"
	"net/url"
	"time"
)

func main() {
	fmt.Println("Hello World!")

	u, _ := url.Parse("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_YqcxrkxxP/.well-known/openid-configuration")

	kc := jwt.NewKeyCache()
	err := kc.AddProvider(u)
	if err != nil {
		panic(err)
	}

	tokenString := "eyJraWQiOiJlZzR0Zmx1RnVlbkFUMHV3azlYT0o3VkhxdEl1SU9DMHJ4dVhEQWZRWjlrPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3cGJvMGZlYTlwZnRmMXVobmNjczVjNms0NSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiZXNiXC9yZWFkLW9ubHktY29tbW9uIGVzYlwvcmVhZC13cml0ZS1jb21tb24iLCJhdXRoX3RpbWUiOjE3NDQ2MDIxMDQsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTIuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0yX1lxY3hya3h4UCIsImV4cCI6MTc0NDYwNTcwNCwiaWF0IjoxNzQ0NjAyMTA0LCJ2ZXJzaW9uIjoyLCJqdGkiOiI2M2NlOWRjYy1lOGU0LTQ5MDMtODJjZS05NzZmMzc5MWZlMTciLCJjbGllbnRfaWQiOiI3cGJvMGZlYTlwZnRmMXVobmNjczVjNms0NSJ9.SiHAlGJIUCJww00zG8WAHtcpaUpaZDSbDytoym0H5wmWvS6VlcEjGH4fFXRXx-ipmn-ZskSl9I1FZgId7q-FDC6XZ6YqLUMU7bGN4RiIxBHfdlItjcCUgqjcpA2g5cwCj9ChphhQ7LI5FLyI4RrA2PaxWhAbauU-t92tTot3NcOtIuXSQ1w7irkIP1ZUBthzEeA2HMcEQ1ywZ5X9EKnhWdJMYDcDZYGV0SxnRqfg8Bon7IiCI6d93GcP2sp90IP4uMsL_A9amGr7Ua0Upx50IeB-5whou_iAIDIkJPRxBm173sw91YDpza8B2YYV_PsDv-xA4UP16pIWfsZV79pe1g"

	_, err = jwt.Parse(tokenString, kc.KeyFunc)
	if err != nil {
		panic(err)
	}

	fmt.Println("Token has been parsed, validated, and verified!")
}

func track(msg string) (string, time.Time) {
	return msg, time.Now()
}

func duration(msg string, start time.Time) {
	log.Printf("%v: %v\n", msg, time.Since(start))
}
