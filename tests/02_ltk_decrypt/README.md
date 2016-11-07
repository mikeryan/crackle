This test validates crackle's LTK decrypt functionality. The packets in
this sample PCAP file are encrypted with the LTK from test 01. By
running crackle in LTK decrypt mode with this LTK, crackle will
successfully decrypt most of the encrypted packets.

To run this test manually:

    crackle -i known_ltk.pcap -o output.pcap -l 7f62c053f104a5bbe68b1d896a2ed49c

Expected output is in ```out/```.
