package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt"
)

var sc = bufio.NewScanner(os.Stdin)

func next() string {
	sc.Scan()
	return sc.Text()
}

func main() {

	var publicKey, jwtToken string

	fmt.Println("### Set Jwt ###")
	jwtToken = next()

	fmt.Println("### Set Public Kye ###")
	publicKey = next()
	publicKey = strings.Replace(publicKey, "-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n", 1)
	publicKey = strings.Replace(publicKey, "-----END PUBLIC KEY-----", "\n-----END PUBLIC KEY-----", 1)

	pkey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		fmt.Printf("Parse RSAPublicKey From PEM Error: %#v\n", err)
		return
	}

	parsedToken, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pkey, nil
	})

	if parsedToken.Valid {
		fmt.Println("### Show Parsed Token ###")
		fmt.Println(parsedToken.Header)
		claims, _ := parsedToken.Claims.(jwt.MapClaims)
		fmt.Println(claims)
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Println("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			fmt.Println("Timing is everything")
		} else {
			fmt.Println("Couldn't handle this token:", err)
		}
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}
}
