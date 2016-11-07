This test validates that crackle's TK cracking with all pairing packets
present functions as expected. If the test succeeds, crackle will
discover that the TK is 000000 (Just Works pairing) and decrypt the
encrypted packets within the PCAP. crackle will extract the LTK that is
exchanged after encryption is established and print it to stdout.

To run this test manually:

    crackle -i pairing_and_ltk_exchange.pcap -o output.pcap

Expected output is in ```out/```.
