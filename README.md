avant
=====
Simple and fast onion balancing.

`avant`

 fetches descriptors for all backend onions, then

 takes all the introduction points from them, then

 reassembles these introduction points into new descriptors, then

 signs the descriptors with frontend onion key, then

 publishes them to HSDir.

So it goes.

Install
-------
```
$ go get -u github.com/nogoegst/avant/cmd/...
```

Usage
-----
Generate a private key:
```
 $ openssl genrsa -out key.pem 1024
```
Steal all intropoints from Facebook:
```
 $ avant -keyfile=key.pem facebookcorewwwi
```
Now your onion service is alive.


`avant` is capabale of creating distinct descriptors (`-distinct-descs` flag)
 in order to fit up to 6x10=60 introduction points per onion service.

`avant` can upload a set of descriptors with specified replica:

   `-replica-mask 010101` - upload descriptors only with replica={1,3,5}

   `-replica-mask 000000` - upload descriptors only with replica={}, i.e. nothing.


Remarks
-------
`avant` avants only once. If you want to do it regulary, there is
`cron` for that. Consult `rend-spec.txt` about the upload intervals.
