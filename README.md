# jwtlib

`jwtlib` is a Go library for generating and validating JWT (JSON Web Tokens) using RSA keys. This library is designed to be simple, flexible, and easy to integrate into your Go applications. Note that this library was made for personal use.

## Features

- Load RSA private and public keys from PEM files
- Generate JWT tokens with custom claims
- Validate JWT tokens with custom validation logic

## Installation

To install the library, run:

```bash
go get github.com/scott-mescudi/jwtlib
```

Make sure to replace `scott-mescudi` with your actual GitHub username or wherever the repository is hosted.

## Usage

### Importing the Package

```go
import "github.com/scott-mescudi/jwtlib"
```

### Loading RSA Keys

You can load your RSA private and public keys from PEM files using the `LoadRSAKeyFromPEM` function.

```go
privateKey, err := jwtlib.LoadRSAKeyFromPEM("path/to/private.pem", "private")
if err != nil {
    log.Fatalf("failed to load private key: %v", err)
}

publicKey, err := jwtlib.LoadRSAKeyFromPEM("path/to/public.pem", "public")
if err != nil {
    log.Fatalf("failed to load public key: %v", err)
}
```

### Generating a JWT Token

You can generate a JWT token with custom claims using the `GenerateToken` function.

```go
claims := jwtlib.DefaultClaims("username", "admin")

token, err := jwtlib.GenerateToken(privateKey.(*rsa.PrivateKey), claims)
if err != nil {
    log.Fatalf("failed to generate token: %v", err)
}

fmt.Printf("Generated Token: %s\n", token)
```

### Validating a JWT Token

You can validate a JWT token and apply custom claim validation using the `ValidateToken` function.

```go
isValid, err := jwtlib.ValidateToken(token, publicKey.(*rsa.PublicKey), func(claims jwt.MapClaims) error {
    // Custom claim validation logic
    if claims["iss"] != "my-auth-server" {
        return errors.New("invalid issuer")
    }

    // Ensure the token is not expired
    if exp, ok := claims["exp"].(float64); ok {
        if time.Now().Unix() > int64(exp) {
            return errors.New("token has expired")
        }
    } else {
        return errors.New("missing expiration claim")
    }

    return nil
})

if err != nil || !isValid {
    log.Fatalf("token validation failed: %v", err)
}

fmt.Println("Token is valid!")
```

### Example Application

Here's a full example of how you might use `jwtlib` in an application:

```go
package main

import (
    "fmt"
    "log"
    "time"
    "crypto/rsa"
    "errors"
    "github.com/scott-mescudi/jwtlib"
)

func main() {
    // Load the RSA keys
    privateKey, err := jwtlib.LoadRSAKeyFromPEM("path/to/private.pem", "private")
    if err != nil {
        log.Fatalf("failed to load private key: %v", err)
    }

    publicKey, err := jwtlib.LoadRSAKeyFromPEM("path/to/public.pem", "public")
    if err != nil {
        log.Fatalf("failed to load public key: %v", err)
    }

    // Generate a JWT token
    claims := jwtlib.DefaultClaims("username", "admin")
    token, err := jwtlib.GenerateToken(privateKey.(*rsa.PrivateKey), claims)
    if err != nil {
        log.Fatalf("failed to generate token: %v", err)
    }

    fmt.Printf("Generated Token: %s\n", token)

    // Validate the JWT token
    isValid, err := jwtlib.ValidateToken(token, publicKey.(*rsa.PublicKey), func(claims jwt.MapClaims) error {
        if claims["iss"] != "my-auth-server" {
            return errors.New("invalid issuer")
        }
        if exp, ok := claims["exp"].(float64); ok {
            if time.Now().Unix() > int64(exp) {
                return errors.New("token has expired")
            }
        } else {
            return errors.New("missing expiration claim")
        }
        return nil
    })

    if err != nil || !isValid {
        log.Fatalf("token validation failed: %v", err)
    }

    fmt.Println("Token is valid!")
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
