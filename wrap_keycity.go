package main

import (
    "crypto/rsa"
    "keycity"
)

// A closure for passing signing funciton
func signWith(onion string) (func(digest []byte) ([]byte, error))  {
    return func(digest []byte) ([]byte, error) {
        return keycity.SignPlease(onion, digest)
    }
}

// A closure for passing public key getting function
func getPubKeyFor(onion string) (pubkey *rsa.PublicKey, err error) {
    return keycity.PubkeyPlease(onion)
}

