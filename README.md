![crackle](https://raw.github.com/mikeryan/crackle/logo/crackle.png "crackle")

crackle cracks BLE Encryption (AKA Bluetooth Smart).

crackle exploits a flaw in the BLE pairing process that allows an
attacker to guess or very quickly brute force the TK (Temporary Key).
With the TK and other data collected from the pairing process, the STK
(Short Term Key) and later the LTK (Long Term Key) can be collected.

With the STK and LTK, all communications between the master and the
slave can be decrypted.

Before attempting to use crackle, review the [FAQ](FAQ.md) to determine
whether it is the appropriate tool to use in your situation.

crackle was written by Mike Ryan <mikeryan@lacklustre.net>
See web site for more info:
    http://lacklustre.net/projects/crackle/

![Build Status](https://travis-ci.org/mikeryan/crackle.svg?branch=master "Build Status")

Table of Contents
=================

 - Modes of Operation
    - Crack TK
    - Decrypt with LTK
 - Running crackle
 - Sample Files
 - Frequently Asked Questions
 - See Also
 - Thanks


Modes of Operation
==================

crackle has two major modes of operation: Crack TK and Decrypt with LTK.

Crack TK
--------

This is the default mode used when providing crackle with an input file
using ```-i```.

In Crack TK mode, crackle brute forces the TK used during a BLE pairing
event. crackle exploits the fact that the TK in Just Works(tm) and
6-digit PIN is a value in the range [0,999999] padded to 128 bits.

crackle employs several methods to perform this brute force: a very fast
method if all pairing packets are present in the input file, and a slow
method if a minimum set of packets is present.

To use this mode, launch crackle with an input PCAP or PcapNG file
containing one or more connections with a BLE pairing conversation.
crackle will analyze all connections, determine whether it is possible
to crack a given connection, and automatically choose the best strategy
to crack each one.

If the TK successfully cracks, crackle will derive the remaining keys
used to encrypt the rest of the connection and will decrypt any
encrypted packets that follow. If the LTK is exchanged (typically the
first thing done after encryption is established) crackle will output
this value to stdout. The LTK can be used to decrypt any future
communications between the two endpoints.

Provide crackle with an output file using ```-o``` to create a new PCAP
file containing the decrypted data (in addition to the already
unencrypted data).

Example usage:

    $ crackle -i input.pcap -o decrypted.pcap


Decrypt with LTK
----------------

In Decrypt with LTK mode, crackle uses a user-supplied LTK to decrypt
communications between a master and slave. This mode is identical to the
decryption portion of Crack TK mode.

Example usage:

    $ crackle -i encrypted.pcap -o decrypted.pcap -l 81b06facd90fe7a6e9bbd9cee59736a7


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

crackle will analyze each connection in the input file and output the
results of its analysis to stdout. If you have all the components of a
pairing conversation, the output will look like this:

    Analyzing connection 0:
      xx:xx:xx:xx:xx:xx (public) -> yy:yy:yy:yy:yy:yy (public)
      Found 13 encrypted packets

      Cracking with strategy 0, 20 bits of entropy

      !!!
      TK found: 412741
      !!!

      Decrypted 12 packets
      LTK found: 81b06facd90fe7a6e9bbd9cee59736a7

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

If you have both of the required packets, the program should produce
output similar to this:

    Analyzing connection 0:
      xx:xx:xx:xx:xx:xx (public) -> yy:yy:yy:yy:yy:yy (public)
      Found 9 encrypted packets
      Decrypted 6 packets

    Specify an output file with -o to decrypt packets!

To decrypt all packets, add the -o option:

    crackle -i <file.pcap> -o <out.pcap> -l <ltk>

The output file will be produced similarly to the output file described
above.


Sample Files
============

The test files included in the ```tests``` directory serve as
interesting input for playing with crackle. Review the README files
included in each test's subdirectory.

Grab some sample files for cracking with crackle. Refer to the README
inside the tarball for more information:

https://lacklustre.net/bluetooth/crackle-sample.tgz


Frequently Asked Questions
==========================

We have compiled a list of [Frequently Asked Questions](FAQ.md).


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
