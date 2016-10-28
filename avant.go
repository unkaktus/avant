// avant.go - tar for onions. Do OnionBalance in unix way.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of avant, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	badrand "math/rand"
	"os"

	"github.com/nogoegst/bulb"
	"github.com/nogoegst/onionutil"
)

const MaxDescriptors = 6
const MaxIntropointsInDesc = 10
const MaxIntropoints = MaxIntropointsInDesc*MaxDescriptors

func shuffleIntroPoints(src, dst []onionutil.IntroductionPoint) {
	perm := badrand.Perm(len(src))
	for index, value := range perm {
		dst[value] = src[index]
	}
}

/* 6-bit mask for 'enable-publish' bit for each replica */
func parseReplicaMask(mask string) (bool_mask [MaxDescriptors]bool, err error) {
	if len(mask) != MaxDescriptors {
		return bool_mask, fmt.Errorf("Wrong mask length - should be %d",
			MaxDescriptors)
	}
	for i, v := range mask {
		if v != '0' {
			bool_mask[i] = true
		} else {
			bool_mask[i] = false
		}
	}
	return bool_mask, nil
}

/* pickIntroPoints picks introduction points from all_ips and populates
 * sets of IPs per replica (ipForReplica) with these IPs. If distinct_descs
 * option is true it does use layover anyway.
 */
func pickIntroPoints(all_ips []onionutil.IntroductionPoint, distinct_descs bool) (
	ipForReplica [][]onionutil.IntroductionPoint) {
	ipForReplica = make([][]onionutil.IntroductionPoint,
		MaxDescriptors)
	shuffleIntroPoints(all_ips, all_ips)
	if len(all_ips) <= MaxIntropointsInDesc && distinct_descs == false {
		for i, _ := range ipForReplica {
			ipForReplica[i] = all_ips
		}
	} else { /* Distinct descriptors mode */
		/* Truncate if it's too many IPs */
		if len(all_ips) > MaxIntropoints {
			all_ips = all_ips[:MaxIntropoints]
		}
		/* Distribute IPs using layover method */
		for i, ip := range all_ips {
			index := i % MaxDescriptors
			ipForReplica[index] = append(ipForReplica[index], ip)
		}
	}
	return ipForReplica
}

func main() {
	var debug_flag = flag.Bool("debug", false,
		"Show what's happening")
	var save_to_files = flag.Bool("save-to-files", false,
		"Save descriptors to files 'onion.replica.desc' in the working directory")
	var distinct_descs = flag.Bool("distinct-descs", false,
		"Force distinct descriptors mode")
	var control = flag.String("control-addr", "default://",
		"Set Tor control address to be used")
	var control_passwd = flag.String("control-passwd", "",
		"Set Tor control auth password")
	var replica_mask = flag.String("replica-mask", "111111",
		"Select replicas to publish descriptors")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [-flags] frontonion backonion1 [backonion2 [...]]\n",
			os.Args[0])
		fmt.Fprintf(os.Stderr, "Available flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	debug := *debug_flag
	var tail = flag.Args()
	switch {
	case len(tail) < 1:
		log.Fatalf("You must specify at least one frontend onion")
	case len(tail) < 2:
		log.Fatalf("You must specify at least one backend onion")
	}
	replicas, err := parseReplicaMask(*replica_mask)
	if err != nil {
		log.Fatalf("Wrong replica mask: %v", err)
	}
	var front_onion = tail[0]
	var onions = tail[1:]

	log.Printf("Trying to get public key for the front onion...")
	perm_pk, err := getPubKeyFor(front_onion)
	if err != nil {
		log.Fatalf("Cannot get front onion pubkey: %v", err)
	}
	// Check if we've got the right key
	permid_from_pk, _ := onionutil.CalcPermanentID(perm_pk)
	if onionutil.Base32Encode(permid_from_pk) != front_onion {
		log.Fatalf("We've got wrong public key for the front onion")
	}
	// Connect to a running tor instance.
	c, err := bulb.DialURL(*control)
	if err != nil {
		log.Fatalf("Failed to connect to control socket: %v", err)
	}
	defer c.Close()

	// See what's really going on under the hood.
	// Do not enable in production.
	c.Debug(debug)

	// Authenticate with the control port.  The password argument
	// here can be "" if no password is set (CookieAuth, no auth).
	if err := c.Authenticate(*control_passwd); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// At this point, c.Request() can be used to issue requests.
	resp, err := c.Request("GETINFO version")
	if err != nil {
		log.Fatalf("GETINFO version failed: %v", err)
	}
	log.Printf("We're using tor %v", resp.Data[0])

	c.StartAsyncReader()

	// Initialize fetches for all the onions
	log.Printf("Sending fetch requests for all descriptors...")
	for _, onion := range onions {
		resp, err := c.Request("HSFETCH %v", onion)
		if err != nil {
			log.Fatalf("HSFETCH failed: %v", err)
		}
		if debug {
			log.Printf("HSFETCH response: %v", resp)
		}
	}

	if _, err := c.Request("SETEVENTS HS_DESC_CONTENT"); err != nil {
		log.Fatalf("SETEVENTS HS_DESC_CONTENT failed: %v", err)
	}

	var descriptors []onionutil.OnionDescriptor
	// XXX: if some onion is broken we're stuck. timeout?

	// Revieve descriptors and parse them
	for len(onions) > 0 {
		ev, err := c.NextEvent()
		if err != nil {
			log.Fatalf("NextEvent() failed: %v", err)
		}
		descContent := []byte(ev.Data[1])
		descs, _ := onionutil.ParseOnionDescriptors(descContent)
		if len(descs) == 0 {
			log.Printf("There are no descriptors in this document. Skipping.")
			if debug {
				log.Printf("Broken response %v", ev)
			}
			continue
		}
		for _, desc := range descs {
			permID, err := onionutil.CalcPermanentID(desc.PermanentKey)
			if err != nil {
				log.Printf("Error in calculating permanent id: %v", err)
				continue
			}
			onion_curr := onionutil.Base32Encode(permID)
			/* Is this onion is among the requested by us? */
			for i, onion := range onions {
				if onion_curr == onion {
					onions = append(onions[:i], onions[i+1:]...)
					log.Printf("Got descriptor for %v.onion "+
						"with %d introduction points. "+
						"%v descriptors left",
						onion_curr,
						len(desc.IntroductionPoints),
						len(onions))
					descriptors = append(descriptors, desc)
					break
				}
			}
		}
	}

	// Gather all the IPs
	all_ips := make([]onionutil.IntroductionPoint,
		0, len(onions)*MaxIntropoints)
	for _, descriptor := range descriptors {
		all_ips = append(all_ips, descriptor.IntroductionPoints...)
	}

	// Pick IPs from the pool
	picked_ips := pickIntroPoints(all_ips, *distinct_descs)
	lens := make([]int, len(picked_ips))
	for i, _ := range picked_ips {
		lens[i] = len(picked_ips[i])
	}
	log.Printf("Using the following IP distribution: %v", lens)

	for replica, do_publish := range replicas {
		desc := onionutil.NewOnionDescriptor(perm_pk, picked_ips[replica], replica)
		signedDesc := desc.Sign(signWith(front_onion))

		if *save_to_files {
			ioutil.WriteFile(fmt.Sprintf("%v.%v.desc", front_onion, replica),
				signedDesc, 0600)
		}
		if do_publish {
			log.Printf("Publishing descriptor under replica #%v", replica)
			resp, _ = c.Request("+HSPOST\n%s.", signedDesc)
			if debug {
				log.Printf("HSPOST response: %v", resp)
			}
		}
	}

	defer c.Close()

}
