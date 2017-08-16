This test demonstrates cracking LE Legacy Pairing using a Numeric PIN.
All previous tests were using the Just Works pairing method which uses a
fixed PIN of 000000. The devices used in this test both supported an
IOCapability of KeyboardDisplay, allowing them to use the marginally
stronger Numeric PIN pairing mode.

An active adversary performing a man-in-the-middle (MitM) attack will
cause a different PIN to be displayed on the endpoint devices with very
high probability. This allows end users to detect that they are being
actively attacked and their data could be tampered with. That being
said, it provides no better protection against passive eavesdropping, as
this test demonstrates!

In this example, the devices calculate a PIN of 461140.

To run this test manually:

    crackle -i numeric_pin.pcap -o output.pcap

Expected output is in ```out/```.
