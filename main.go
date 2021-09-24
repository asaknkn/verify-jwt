package main

import (
	"bufio"
	"encoding/base64"
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

func errorCheck(parsedToken *jwt.Token, err error) error {
	if parsedToken.Valid {
		return nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return fmt.Errorf("that's not even a token: %v", err)
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			return fmt.Errorf("timing is everything: %v", err)
		} else {
			return fmt.Errorf("couldn't handle this token: %v", err)
		}
	} else {
		return fmt.Errorf("couldn't handle this token: %v", err)
	}
}

func rsaJwtVerify() {
	fmt.Println("### Set Jwt ###")
	jwtToken := next()

	fmt.Println("### Set Public Kye ###")
	publicKey := next()
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

	checkedError := errorCheck(parsedToken, err)
	if checkedError != nil {
		fmt.Println(checkedError)
		return
	}

	fmt.Println("### Show Parsed Token ###")
	fmt.Println(parsedToken.Header)
	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	fmt.Println(claims)
}

func hamcJwtVerify() {
	fmt.Println("### Set Jwt ###")
	jwtToken := next()

	fmt.Println("### Set Secret Kye ###")
	secretKey := next()

	hamcSecret, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		fmt.Println("Base64 Decode Error:", err)
	}

	parsedToken, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return hamcSecret, nil
	})

	checkedError := errorCheck(parsedToken, err)
	if checkedError != nil {
		fmt.Println(checkedError)
		return
	}

	fmt.Println("### Show Parsed Token ###")
	fmt.Println(parsedToken.Header)
	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	fmt.Println(claims)
}

func main() {

	fmt.Println("alg: rsa or hmac")
	alg := next()

	switch alg {
	case "rsa":
		rsaJwtVerify()
	case "hmac":
		hamcJwtVerify()
	default:
		fmt.Println("Set correct alg")
	}
}
