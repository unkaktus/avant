// avant.go - tar for onions. Do OnionBalance in unix way.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of avant, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nogoegst/avant"
	"github.com/nogoegst/onionutil"
)

// TODO: drop this function and use csv instead
/* 6-bit mask for 'enable-publish' bit for each replica */
func parseReplicaMask(mask string) (replicas []int, err error) {
	if len(mask) != avant.MaxDescriptors {
		return replicas, fmt.Errorf("wrong mask length - should be %d", avant.MaxDescriptors)
	}
	for i, v := range mask {
		switch v {
		case '0':
		case '1':
			replicas = append(replicas, i)
		default:
			return replicas, fmt.Errorf("invalid chars in mask string")
		}
	}
	return
}

func main() {
	var debugFlag = flag.Bool("debug", false,
		"Show what's happening")
	var distinctDescs = flag.Bool("distinct-descs", false,
		"Force distinct descriptors mode")
	var controlURL = flag.String("control-addr", "default://",
		"Set Tor control address to be used")
	var controlPassword = flag.String("control-passwd", "",
		"Set Tor control auth password")
	var replicaMask = flag.String("replica-mask", "11",
		"Select replicas to publish descriptors")
	var keyfileFlag = flag.String("keyfile", "",
		"Path to the fronting keyfile")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [-flags] backonion1 [backonion2 [...]]\n",
			os.Args[0])
		fmt.Fprintf(os.Stderr, "Available flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	replicas, err := parseReplicaMask(*replicaMask)
	if err != nil {
		log.Fatalf("Wrong replica mask: %v", err)
	}
	a := &avant.Avanter{
		Debug:               *debugFlag,
		Replicas:            replicas,
		DistinctDescriptors: *distinctDescs,
	}
	if err := a.Connect(*controlURL, *controlPassword); err != nil {
		log.Fatal(err)
	}
	onions := flag.Args()
	if len(onions) < 1 {
		log.Fatalf("You must specify at least one backend onion")
	}

	frontSK, frontPK, err := onionutil.LoadPrivateKeyFile(*keyfileFlag)
	if err != nil {
		log.Fatalf("Unable to load private key: %v", err)
	}
	descs, err := a.ProduceBalancedDescriptors(onions...)
	if err != nil {
		log.Fatal(err)
	}
	frontSigner, ok := frontSK.(crypto.Signer)
	if !ok {
		log.Fatal("cannot sign with private key")
	}
	for i, _ := range descs {
		if err := descs[i].FullSign(frontSigner); err != nil {
			log.Fatal(err)
		}
	}
	err = a.PublishDescriptors(descs...)
	if err != nil {
		log.Fatal(err)
	}
	frontonion, err := onionutil.OnionAddress(frontPK)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("completed balancing for %s.onion", frontonion)
}
