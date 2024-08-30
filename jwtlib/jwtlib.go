package jwtlib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidKeyType is returned when the provided key type is not "private" or "public".
	ErrInvalidKeyType = errors.New("invalid key type")
)

// LoadRSAKeyFromPEM loads an RSA key (private/public) from a PEM file.
// keyType should be either "private" or "public".
func LoadRSAKeyFromPEM(pemFile string, keyType string) (interface{}, error) {
	pemData, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("could not read PEM file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch keyType {
	case "private":
		if block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("expected RSA PRIVATE KEY, got %s", block.Type)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "public":
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("expected PUBLIC KEY, got %s", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if publicKey, ok := pub.(*rsa.PublicKey); ok {
			return publicKey, nil
		}
		return nil, errors.New("not an RSA public key")
	default:
		return nil, ErrInvalidKeyType
	}
}

// GenerateToken creates a signed JWT using the provided private RSA key and claims.
func GenerateToken(key *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// ValidateToken verifies the provided JWT using the public RSA key and custom validation function.
func ValidateToken(s string, key *rsa.PublicKey, validateClaims func(claims jwt.MapClaims) error) (bool, error) {
	token, err := jwt.Parse(s, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if err := validateClaims(claims); err != nil {
			return false, err
		}
		return true, nil
	}

	return false, fmt.Errorf("invalid token")
}

// DefaultClaims returns a set of default JWT claims.
func DefaultClaims(iss, username, audience string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":      iss,
		"username": username,
		"aud":      audience,
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}
}
