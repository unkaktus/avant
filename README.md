avant
=====
OnionBalance in unix way.

`avant`

 fetches descriptors for all backend onions, then

 takes all the introduction points from them, then

 reassembles these introduction points into new descriptor(s), then

 signs the descriptor(s) with frontend onion key, then

 publishes it(them) to HSDir.

So it goes.

Install
-------
```
$ torsocks go get github.com/nogoegst/avant
```

Usage
-----
Let's say that your private (1024-bit RSA, PEM-formatted) keys
are stored in `/path/to/keys`.
```
$ export KEYCITYPATH=/path/to/keys
$ avant frontonion backonion1 backonion2
```

`avant` is capabale of creating distinct descriptors (`-distinct-descs` flag)
 in order to fit up to 6x10=60 introduction points per onion service.

`avant` can upload a set of descriptors with specified replica:

   `-replica-mask 010101` - upload descriptors only with replica={1,3,5}

   `-replica-mask 000000` - upload descriptors only with replica={}, i.e. nothing.

`avant` can save descriptors to files via `-save-to-files` flag.

Remarks
-------
`avant` just `avant`s once. If you want to do it regulary, there is
`cron` for that. Please consult `rend-spec.txt` about the upload intervals.

At the moment `avant` depends on a shitty version of `keycity` and 
may be inconvenient as hell (with all these env variables etc).
It's not going to always be like that, so don't blame me for that.
