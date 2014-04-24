![crackle](https://raw.github.com/mikeryan/crackle/logo/crackle.png "crackle")

crackle cracks BLE Encryption (AKA Bluetooth Smart).

crackle exploits a flaw in the BLE pairing process that allows an
attacker to guess or very quickly brute force the TK (Temporary Key).
With the TK and other data collected from the pairing process, the STK
(Short Term Key) and later the LTK (Long Term Key) can be collected.

With the STK and LTK, all communications between the master and the
slave can be decrypted.

crackle was written by Mike Ryan <mikeryan@lacklustre.net>
See web site for more info:
    http://lacklustre.net/projects/crackle/


Table of Contents
=================

 - Modes of Operation
    - Crack TK
    - Decrypt with LTK
 - Running crackle
 - Sample Files
 - See Also
 - Thanks


Modes of Operation
==================

crackle has two major modes of operation: Crack TK and Decrypt with LTK.

Crack TK
--------

In Crack TK mode, crackle brute forces the TK used during a BLE pairing
event. crackle exploits the fact that the TK in Just Works(tm) and
6-digit PIN is a value in the range [0,999999] padded to 128 bits. The
brute force process takes less than one second on modern CPUs.

After the TK has been cracked, crackle goes on to derive the remaining
keys used to encrypt further communication and uses these to decrypt the
encrypted L2CAP data. If the LTK is exchanged (typically the first order
of business after encrypted communication is established), crackle
outputs this value. The LTK can be used to decrypt any future
communicaitons between the master and slave.

Decrypt with LTK
----------------

In Decrypt with LTK mode, crackle uses a user-supplied LTK to decrypt
communications between a master and slave. This mode is identical to the
decryption portion of Crack TK mode.


Running Crackle
===============

Crack TK Mode
-------------

In Crack TK mode, crackle requires a PCAP file that contains a BLE
pairing event. The best way to generate such a file is to use an
Ubertooth to capture a pairing event between a master and a slave.

To check if your PCAP file contains all the necessary packets, run
crackle with the -i option:

    crackle -i <file.pcap>

If you have all packets, the program should produce output similar to
this:

    Warning: No output file specified. Won't decrypt any packets.
    TK found: 412741
    Specify an output file with -o to decrypt packets!

To decrypt all packets, add the -o option:

    crackle -i <file.pcap> -o <output.pcap>

The output file will contain decrypted versions of all the encrypted
packets from the original PCAP, as well as all the unencrypted packets.
Note that CRCs are not recalculated, so the CRCs of decrypted packets
will be incorrect.

Decrypt with LTK
----------------

In Decrypt with LTK mode, crackle requires a PCAP file that contains at
a minimum LL_ENC_REQ and LL_ENC_RSP packets and the LTK used to encrypt
the communications.

The format for LTK is a 128 bit hexadecimal number with no spaces or
separators, most-significant octet to least-significant octet. Example:

    -l 81b06facd90fe7a6e9bbd9cee59736a7

To check if your PCAP file contains all the necessary packets, run
crackle with -i and -l:

    crackle -i <file.pcap> -l <ltk>

If you have all the packets, the program should produce output similar
to this:

    Warning: No output file specified. Won't decrypt any packets.
    Specify an output file with -o to decrypt packets!

To decrypt all packets, add the -o option:

    crackle -i <file.pcap> -o <out.pcap> -l <ltk>

The output file will be produced similarly to the output file described
above.


Sample Files
============

Grab some sample files for cracking with crackle. Refer to the README
inside the tarball for more information:

https://lacklustre.net/bluetooth/crackle-sample.tgz


See Also
========

 - Ubertooth: http://ubertooth.sourceforge.net/
 - libbtbb: http://libbtbb.sourceforge.net/
 - #ubertooth on irc.freenode.net


Thanks
======

Major thanks go to Mike Ossmann and Dominic Spill from the Ubertooth
project. None of this would be possible without them.

Big time thanks go to Mike Kershaw/dragorn of Kismet for help creating
and working with PCAP files.

Thanks go to the rest of #ubertooth on irc.freenode.net.
