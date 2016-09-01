// avant.go - tar for onions. Do OnionBalance in unix way.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of avant, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
    "flag"
    "log"
    "os"
    "io/ioutil"
    "fmt"
    badrand "math/rand"
    "github.com/nogoegst/onionutil"
    "github.com/nogoegst/onionutil/intropoint"
    "github.com/nogoegst/onionutil/oniondesc"
    "github.com/nogoegst/bulb"
    bulbUtils "github.com/nogoegst/bulb/utils"
)

const MAX_REPLICA_NUMBER = 6
const MAX_INTROPOINT_NUMBER = 10

func shuffleIntroPoints(src []intropoint.IntroductionPoint) (
                        dst []intropoint.IntroductionPoint) {
    dst = make([]intropoint.IntroductionPoint, len(src))
    perm := badrand.Perm(len(src))
    for index,value := range perm {
        dst[value] = src[index]
    }
    return dst
}

/* 6-bit mask for 'enable-publish' bit for each replica */
func parseReplicaMask(mask string)(bool_mask [MAX_REPLICA_NUMBER]bool, err error) {
    if len(mask) != MAX_REPLICA_NUMBER {
        return bool_mask, fmt.Errorf("Wrong mask length - should be %d",
                                     MAX_REPLICA_NUMBER)
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
func pickIntroPoints(all_ips []intropoint.IntroductionPoint, distinct_descs bool) (
                     ipForReplica [][]intropoint.IntroductionPoint) {
    ipForReplica = make([][]intropoint.IntroductionPoint,
                             MAX_REPLICA_NUMBER)
    all_ips = shuffleIntroPoints(all_ips)
    if (len(all_ips) <= MAX_INTROPOINT_NUMBER && distinct_descs == false) {
        for i, _ := range ipForReplica {
            ipForReplica[i] = all_ips
        }
    } else { /* Distinct descriptors mode */
        /* Truncate if it's too many IPs */
        if len(all_ips) > MAX_REPLICA_NUMBER*MAX_INTROPOINT_NUMBER {
            all_ips = all_ips[:MAX_REPLICA_NUMBER*MAX_INTROPOINT_NUMBER]
        }
        /* Distribute IPs using layover method */
        for i, ip := range all_ips {
            index := i%MAX_REPLICA_NUMBER
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
    var control = flag.String("control-addr", "tcp://127.0.0.1:9051",
        "Set Tor control address to be used")
    var control_passwd = flag.String("control-passwd", "",
        "Set Tor control auth password")
    var replica_mask = flag.String("replica-mask","111111",
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
    permid_from_pk, _ := onionutil.CalcPermanentId(perm_pk)
    if onionutil.Base32Encode(permid_from_pk) != front_onion {
        log.Fatalf("We've got wrong public key for the front onion")
    }
    // Parse control string
    control_net, control_addr, err := bulbUtils.ParseControlPortString(*control)
    if err != nil {
        log.Fatalf("Failed to parse Tor control address string: %v", err)
    }
    // Connect to a running tor instance.
    c, err := bulb.Dial(control_net, control_addr)
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

    var descriptors []oniondesc.OnionDescriptor
    // XXX: if some onion is broken we're stuck. timeout?

    // Revieve descriptors and parse them
    for len(onions) > 0 {
		ev, err := c.NextEvent()
		if err != nil {
			log.Fatalf("NextEvent() failed: %v", err)
		}
        desc_content_str := ev.Data[1]
        descs, _  := oniondesc.ParseOnionDescriptors(desc_content_str)
        if len(descs) == 0  {
            log.Printf("There are no descriptors in this document. Skipping.")
            if (debug) {
                log.Printf("Broken response %v", ev)
            }
            continue
        }
        for _, desc := range descs {
            perm_id, err := onionutil.CalcPermanentId(desc.PermanentKey)
            if err != nil {
                log.Printf("Error in calculating permanent id: %v", err)
                continue
            }
            onion_curr := onionutil.Base32Encode(perm_id)
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
    all_ips := make([]intropoint.IntroductionPoint,
                    0, len(onions)*MAX_INTROPOINT_NUMBER)
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
        desc := oniondesc.ComposeDescriptor(perm_pk, picked_ips[replica], replica)
        desc_body := oniondesc.MakeDescriptorBody(desc)
        signed_desc := oniondesc.SignDescriptor(desc_body, signWith(front_onion))

        if (*save_to_files) {
            ioutil.WriteFile(fmt.Sprintf("%v.%v.desc", front_onion, replica),
                             []byte(signed_desc), 0600)
        }
        if do_publish {
            log.Printf("Publishing descriptor under replica #%v", replica)
            resp, _ = c.Request("+HSPOST\n%s.", signed_desc)
            if debug {
                log.Printf("HSPOST response: %v", resp)
            }
        }
    }

    defer c.Close()

}
