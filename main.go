package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/ecdsa-generate", ecdsaGenerate)
	http.HandleFunc("/ecdsa-auth", ecdsaAuth)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("ListenAndServe", err)
	}
}

// instead of DB
var clientMap = map[string]*ecdsa.PublicKey{}

var (
	EcdsaPublicKey       string
	EcdsaPrivateKey      string
	ErrUnauthorized      = errors.New("client unauthorized")
	ErrClientKeyNotFound = errors.New("client key not found")
)

func init() {
	EcdsaPublicKey = os.Getenv("ECDSA_PUBKEY")
	EcdsaPrivateKey = os.Getenv("ECDSA_PRIKEY")
}

func login(w http.ResponseWriter, r *http.Request) {
	verifyBytes, err := ioutil.ReadFile(EcdsaPublicKey)
	if err != nil {
		panic(err)
	}
	verifyKey, err := jwt.ParseECPublicKeyFromPEM(verifyBytes)
	if err != nil {
		panic(err)
	}
	clientMap["test"] = verifyKey

	fmt.Fprintln(w, "SUCCESS: userName set - test")
	w.WriteHeader(http.StatusOK)
}

func ecdsaGenerate(w http.ResponseWriter, r *http.Request) {
	if len(clientMap) == 0 {
		fmt.Fprintln(w, "do curl localhost:8080/login first")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	signBytes, err := ioutil.ReadFile(EcdsaPrivateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	signKey, err := jwt.ParseECPrivateKeyFromPEM(signBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	token := jwt.New(jwt.SigningMethodES256)

	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "test"
	claims["exp"] = time.Now().Add(time.Hour * 15).Unix()

	tokenString, err := token.SignedString(signKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func ecdsaAuth(w http.ResponseWriter, r *http.Request) {
	token, err := fromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientID := getClientID(token)
	if err := verify(token, clientID); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "SUCCESS: userName - %s", clientID)
	w.WriteHeader(http.StatusOK)
}

func fromAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header should be provided")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

func getClientID(tokenStr string) string {
	claims := &jwt.StandardClaims{}
	_, _ = jwt.ParseWithClaims(tokenStr, claims, nil)
	return claims.Subject
}

func verify(tokenStr, clientID string) error {
	verifyKey, ok := clientMap[clientID]
	if !ok {
		return ErrClientKeyNotFound
	}
	return _verify(tokenStr, verifyKey)
}

func _verify(tokenStr string, verifyKey *ecdsa.PublicKey) error {
	claims := &jwt.StandardClaims{}
	jt, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return verifyKey, nil
	})
	if err != nil || !jt.Valid {
		return ErrUnauthorized
	}
	return nil
}
