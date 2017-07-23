// avant.go - tar for onions. Do OnionBalance in unix way.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of avant, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package avant

import (
	"fmt"
	"log"

	"github.com/nogoegst/bulb"
	"github.com/nogoegst/onionutil"
	"github.com/nogoegst/rand"
)

const MaxDescriptors = 2
const MaxIntropointsInDesc = 10
const MaxIntropoints = MaxIntropointsInDesc * MaxDescriptors

func shuffleIntroPoints(src, dst []onionutil.IntroductionPoint) {
	perm := rand.Perm(len(src))
	for index, value := range perm {
		dst[value] = src[index]
	}
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

type Avanter struct {
	c                   *bulb.Conn
	Debug               bool
	DistinctDescriptors bool
	Replicas            []int
}

func (a *Avanter) Connect(controlURL string, controlPassword string) error {
	c, err := bulb.DialURL(controlURL)
	if err != nil {
		return fmt.Errorf("failed to connect to control socket: %v", err)
	}
	a.c = c
	a.c.Debug(a.Debug)
	if err := a.c.Authenticate(controlPassword); err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}
	a.c.StartAsyncReader()
	return nil
}

func (a *Avanter) ProduceBalancedDescriptors(onions ...string) ([]onionutil.OnionDescriptor, error) {
	if a.Debug {
		log.Printf("Sending fetch requests for all descriptors...")
	}
	for _, onion := range onions {
		resp, err := a.c.Request("HSFETCH %v", onion)
		if err != nil {
			return nil, fmt.Errorf("HSFETCH failed: %v", err)
		}
		if a.Debug {
			log.Printf("HSFETCH response: %v", resp)
		}
	}

	if _, err := a.c.Request("SETEVENTS HS_DESC_CONTENT"); err != nil {
		return nil, fmt.Errorf("SETEVENTS HS_DESC_CONTENT failed: %v", err)
	}

	allIPs := make([]onionutil.IntroductionPoint, 0, len(onions)*MaxIntropoints)

	// XXX: if some onion is broken we're stuck. timeout?

	// Revieve descriptors and parse them
	for len(onions) > 0 {
		ev, err := a.c.NextEvent()
		if err != nil {
			return nil, fmt.Errorf("NextEvent() failed: %v", err)
		}
		descContent := []byte(ev.Data[1])
		descs, _ := onionutil.ParseOnionDescriptors(descContent)
		if len(descs) == 0 {
			if a.Debug {
				log.Printf("There are no descriptors in this document. Skipping.")
				log.Printf("The broken response was: %+v", ev)
			}
			continue
		}
		for _, desc := range descs {
			currentOnion, err := desc.OnionID()
			if err != nil {
				if a.Debug {
					log.Printf("%v", err)
				}
				continue
			}
			/* Is this onion is among the requested by us? */
			// XXX replace with a map
			for i, onion := range onions {
				if currentOnion == onion {
					onions = append(onions[:i], onions[i+1:]...)
					ipsFromDesc, _ := onionutil.ParseIntroPoints(desc.IntropointsBlock)
					allIPs = append(allIPs, ipsFromDesc...)
					if a.Debug {
						log.Printf("Got descriptor for %v.onion "+
							"with %d introduction points. "+
							"%v descriptors left",
							currentOnion,
							len(ipsFromDesc),
							len(onions))
					}
					break
				}
			}
		}
	}

	// Pick IPs from the pool
	picked_ips := pickIntroPoints(allIPs, a.DistinctDescriptors)
	lens := make([]int, len(picked_ips))
	for i, _ := range picked_ips {
		lens[i] = len(picked_ips[i])
	}
	if a.Debug {
		log.Printf("Using the following IP distribution: %v", lens)
	}

	balancedDescriptors := []onionutil.OnionDescriptor{}
	for _, replica := range a.Replicas {
		desc := new(onionutil.OnionDescriptor)
		desc.InitDefaults()
		desc.Replica = replica
		for _, ip := range picked_ips[replica] {
			desc.IntropointsBlock = append(desc.IntropointsBlock, ip.Bytes()...)
		}
		balancedDescriptors = append(balancedDescriptors, *desc)
	}
	return balancedDescriptors, nil
}

func (a *Avanter) PublishDescriptors(descs ...onionutil.OnionDescriptor) error {
	for _, desc := range descs {
		resp, err := a.c.Request("+HSPOST\n%s.", desc.Bytes())
		if err != nil {
			return err
		}
		if a.Debug {
			log.Printf("HSPOST response: %v", resp)
		}
	}
	return nil
}
