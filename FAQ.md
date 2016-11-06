Frequently Asked Questions
==========================

Much of this document assumes the user is attempting to reverse engineer
a BLE device. If you plan to use Crackle for other purposes much of this
document will not apply to you, but you're probably smart enough to
figure things out on your own.

- [When should I use Crackle?](#when-should-i-use-crackle)
- [Can I log data without having to sniff?](#can-i-log-data-without-having-to-sniff)
- [Is my device using Link Layer encryption?](#is-my-device-using-link-layer-encryption)
- [Is my device using LE Legacy Pairing or LE Secure Connections?](#is-my-device-using-le-legacy-pairing-or-le-secure-connections)
- [Crackle is complaining about missing packets, why can't I crack?](#crackle-is-complaining-about-missing-packets-why-cant-i-crack)


When should I use Crackle?
--------------------------

Crackle is useful when you have sniffed a BLE connection that uses Link
Layer encryption and LE Legacy pairing. Before attempting to use
Crackle, it's worth asking the following questions:

1. Can I log the data without having to sniff it at all?
2. If not, is my device actually using Link Layer encryption?
3. Is the device using Legacy Pairing or LE Secure Connections?

If the answers to these questions are "no", "yes", and "legacy pairing",
Crackle is the right tool for the job.


Can I log data without having to sniff?
---------------------------------------

All BLE connections consist of two endpoints, and commonly one of those
endpoints is a smartphone or a PC. In this scenario, it's very likely
that you can log the data on that endpoint before it is sent over the
air.

This technique has many benefits. It is guaranteed to capture all
data sent between the two devices (Ubertooth is much less reliable).
Additionally, if the devices are using Link Layer encryption, the data
will be captured before it is encrypted.

The only case in which you must sniff using Ubertooth is when it is
impossible to log data directly on either end of the connection. One
example of this is Boosted electric skateboards: the connection
endpoints are the handheld remote and the skateboard. Since both ends
are embedded devices, it is not possible to directly log and therefore
one must sniff using Ubertooth.

On Android, use the [HCI Packet Logging feature](http://stackoverflow.com/questions/23877761/sniffing-logging-your-own-android-bluetooth-traffic).

An updated version of this document will include instructions for how to
do this on Linux, Mac OS X, and iOS.


Is my device using Link Layer encryption?
-----------------------------------------

In the author's experience, relatively few devices make use of LE Link
Layer encryption. Most encrypt their data using custom algorithms
specific to the device. In this case, Crackle is not useful and cannot
assist in cracking key exchange or decrypting data.

Crackle itself can help determine whether or not there are Link Layer
encrypted packets in a given PCAP or PcapNG file. Simply run the tool
without any extra options and it will list how many encrypted packets it
finds for each connection in the input:

    $ crackle -i input.pcap
    ...
    Analyzing connection n:
      xx:xx:xx:xx:xx:xx (public) -> yy:yy:yy:yy:yy:yy (public)
      Found 13 encrypted packets

If this number is non-zero, then the device is likely using Link Layer
encryption.

You can also use Wireshark to look for such packets. Load your capture
file and apply the filter "btle.data_header.length > 0". Link Layer
encrypted packets will look like an L2CAP fragment of non-zero length
with random-looking data as in the following screenshot:

![Encrypted data in Wireshark](doc/encrypted_data.png?raw=true "Encrypted data in Wireshark")


Is my device using LE Legacy Pairing or LE Secure Connections?
--------------------------------------------------------------

Bluetooth 4.2 introduced LE Secure Connections, an ECDH-based pairing
mechanism designed to mitigate the attacks implemented in Crackle.

If your device is using Link Layer encryption, then you need to
determine whether your devices are using LE Legacy Pairing (the older,
vulnerable mechanism) or LE Secure Connections. The majority of devices
using Link Layer encryption at the time of this writing (late 2016) are
using LE Legacy Pairing.

Crackle can help determine whether the devices are using LE Secure
Connections. Run Crackle on your input file without an extra options and
it will throw an error if it detects the pairing packets used by LE
Secure Connections:

    $ crackle -i input.pcap
    ...
    Analyzing connection n:
      xx:xx:xx:xx:xx:xx (public) -> yy:yy:yy:yy:yy:yy (public)
      Found 11 encrypted packets
      Unable to crack due to the following error:
        LE Secure Connections

Note that this test only reports if it positively identifies the LE
Secure Connections pairing packets. This test cannot determine whether
LE Secure Connections are in use if those packets are not captured by
Ubertooth or if the pairing conversation is not present (i.e.,
re-establishing encryption with a previously-paired device).


Crackle is complaining about missing packets, why can't I crack?
----------------------------------------------------------------

Crackle employs several strategies for cracking the LE Legacy Pairing
key exchange, and they all rely on a certain number of packets being
present in the PCAP or PcapNG file. Two major challenges make satisfying
this requirement difficult.

First, Ubertooth does not capture 100% of packets. Ubertooth will not
capture 100% of connections due to the nature of BLE, and even when it
does capture a connection, it will not capture 100% of the packets sent
over the air.

Second, Crackle must observe the key exchange when it occurs. If two
devices have previously paired and are re-establishing encryption,
they will reuse a previously exchanged LTK to secure that connection and
will not perform a key exchange. Crackle cannot be used in this scenario
unless the LTK is already known (for example, by having sniffed and
cracked the earlier key exchange).

A complete pairing conversation looks like the following screenshot from
Wireshark:

![Pairing in Wireshark](doc/complete_pairing.png?raw=true "Pairing in Wireshark")

This includes the CONNECT_REQ establishing the connection, Pairing
Request and Pairing Response, two random values, two confirms,
LL_ENC_REQ, LL_ENC_RSP, and LL_START_ENC_REQ. With all of these values,
Crackle can use the fast algorithm to brute force the TK.

The absolute minimum required packets are the two random values,
LL_ENC_REQ, LL_ENC_RSP, and LL_START_ENC_REQ. With just these packets
Crackle will perform the slower STK brute force implemented by Jelte
Fennema.

If any of the required values is missing, you must repeat the process of
unpairing the devices, re-capturing the connection with Ubertooth, and
re-pairing the devices until all of the necessary packets have been
captured.
