This test validates that crackle's TK cracking succeeds with the minimum
required packets. The input file is identical to test 01, but the
pairing confirm packets have been removed. If the test succeeds, crackle
will determine that it must use the slow STK brute force strategy and
will discover that the TK is 000000. Like test 01, it will decrypt the
encrypted packets and dump the LTK to stdout.

To run this test manually:

    crackle -i missing_confirms.pcap -o output.pcap

Expected output is in ```out/```.
