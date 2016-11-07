This test validates that crackle correctly detects when LE Secure
Connections are in use. Upon discovering an LE SC pairing packet,
crackle will immediately throw an error and fail to crack the pairing.

To run this test manually:

    crackle -i le_secure_connections.pcapng

Expected output is in ```out/```.
