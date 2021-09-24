package main

import (
	"fmt"

	"github.com/golang-jwt/jwt"
)

func main() {

	var publicKey, jwtToken string

	fmt.Println("Set Jwt")
	fmt.Scan(&jwtToken)
	fmt.Println("Set Public Kye")
	fmt.Scan(&publicKey)

	pkey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

	if err != nil {
		fmt.Printf("Parse RSA Error: %#v\n", err)
	}

	parsedToken, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pkey, nil
	})

	if err != nil {
		fmt.Printf("Parse Error: %#v\n", err)
	}
	if !parsedToken.Valid {
		fmt.Println("Token is invalid")
	}

	fmt.Println("### Show Parsed Token ###")
	fmt.Println(parsedToken)
}
