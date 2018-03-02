# TspSign

This is a Java Card Applet implementation as a proof-of-concept of my proposed technique to secure digital sign process in a smart card.
You can find project details in the attached paper in PDF format.

I used a proposed technique called "one-time scanning" to decode DER and TLV format inside the smart card with limited resource and performance. My test results demonstrate that this new technique works well for smart card.

In this project you can find decoder for digital certificate, timestamp token, certificate revocation list (CLR). Actually, you can use TLV engine to decode every DER-encoded content inside the smart card. You must define a template for your content and then you can decode it in the card. There are two different version of TLV decoder in the source code: TLV and TLV2. The file "TLV.java" is classic version of TLV decoder which is fully dynamic and can decode all DER-encoded content but is slow in the smart card. The file "TLV2.java" is the faster version which uses one-time scanning technique.

I used hard-coded 1024 and 2048 RSA keys to test the proposed protocol, and if you like real-world keys, you must change hard-coded keys with new commands to generate RSA keys on card.

To compile the TspSign source code, I use Java Card 2.2.2 specification. For convenience I use JCIDE to develop, emulate and debug TspSign source code.

https://javacardos.com/tools/

To load complied applet to physical smart card, you must have a PC/SC smart card reader, and you can use gp.exe command tool.

https://github.com/martinpaljak/GlobalPlatformPro

On Windows just run:

List all installed applet in the smart card:

gp.exe -l

Load TspSign applet to the smart card:

gp.exe -install TspSign.cap

Delete TspSign applet from the smart card:

gp.exe -delete 1122334455

Application ID (AID) of TspSign is 1122334455. You can change it if you like.

TspSign APDU commands:

Get nonce:
00 84 00 00 08

Verify PIN:
00 20 00 80 04 31323334

Fill card buffer (if your card does not support extended length):
00 CC P1 P2 00 LL LL [CHUNK]
P1 and P2: offset
LL LL: chunk size
CHUNK: part of data

TSP Sign:

00 87 P1 P2 00 LL LL [DATA]

P1 = 01:RSA1024 or 02:RSA2048

P2 = 01:ClassicRSA or 02:CRT_RSA(faster version)

LL LL: length of data in two bytes

Read signature from buffer ((if your card does not support extended length):
00 C0 P1 P2 02 LL LL
P1 and P2: offset
LL LL: length of data

Classic Sign (no tspSign):
00 86 P1 P2 00 LL LL [DATA]
P1 = 01:RSA1024 or 02:RSA2048

P2 = 01:ClassicRSA or 02:CRT_RSA(faster version)
LL LL: length of data in two bytes

