# kirbi2hashcat

1. The repo explains the "ASN.1" codec used by the Kerberos protocol, with reference to the respective RFCs.
2. The script decode binary Kerberos tickets (.kirbi, KRB-CRED) to hashcat recognizable format.
   - Bugfix
   - Add detailed comments and references.
   - Add support for etype 17 and 18

## Usage

```sh
# pip3 install pyasn1
python3 kirbi2hashcat.py example/MSSQLSvc-sql01.medin.local.kirbi
```

## "ASN.1" And The Format Of A Binary Kerberos Ticket

```sh
> xxd example/MSSQLSvc-sql01.medin.local.kirbi
# 00000000: 7682 0550 3082 054c a003 0201 05a1 0302  v..P0..L........
# 00000010: 0116 a282 0461 3082 045d 6182 0459 3082  .....a0..]a..Y0.
```

- The `example/*.kirbi` and `example/TGS-REP.bin` are two binary Kerberos tickets.
  - The first binary can be a mimikatz dump.
  - The second binary can be found in a raw TGS-REP network packet.
- They are both in "ASN.1".BER format, which is defined in "ASN.1".
  - "ASN.1" is a widely used serialization protocol that enables cross-platform data communication.
  - The "BER" stands for "Basic Encoding Rules". It is one of the encoding schemes defined in "ASN.1".
  - Kerberos v5 may use "DER" or "BER" ([RFC4120, p123](https://www.rfc-editor.org/rfc/rfc4120#page-123)).
  - For simplicity, we only discuss the "BER" in this repo.


### "ASN.1".BER Codec And The First 4 Bytes "0x7682 0550"

- "ASN.1".BER encodes data in the "Tag-Length-Value (TLV)" order. (A brief explanation: [ASN1.BER Quick Reference](https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html))
- `0x76` is the "Tag" in TLV
  - `0x76` -> `0b01_1_10110`
  - `01`: the "Class" is "application"
  - `1` : the "Form" is "constructed"; indicating that the "Value" in the TLV may include another "type" (e.g. SEQUENCE) defined in the "ASN.1"
  - `10110` : 22; the "Number", or "Application tag number"; 22 is defined in the Kerberos RFC, means "KRB-CRED" (ref: [RFC4120, The Kerberos Network Authentication Service (V5), Kerberos Application Tag Numbers](https://www.rfc-editor.org/rfc/rfc4120#page-96))
- `0x82 0550` is the "Length" in TLV
  - `0x82` -> `0b1_0000010`; indicates how "Length" is encoded
  - `1`: since the `0000010` != `0`, it means the "Length" in TLV is encoded in "Long form" (quick reference: [ASN1.BER Quick Reference](https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html));
  - `0000010`: 2; the next 2 bytes (i.e. `0x0550`), are the length of the "Value" in TLV
  - `0x0550`: the length of the "Value" in TLV is 0x550 bytes

- Similarly, if the first byte is `0x6d` (`0b01_1_01101`), it means "APPLICATION 13", "TGS-REP", which can be found in a tshark ".pcap". See example/TGS-REP.bin


### The Other Data "0x30..."

- The rest of the data is the "Value" in the TLV
- `0x30` is also the "Tag" for the first child, in TLV notation; in this case means a "SEQUENCE"
  - `0x30` -> `0b00_1_10000`
  - `00`: the "Class" is "universal"
  - `1` : the "Form" is "constructed"
  - `10000`: 16; given "universal", "constructed", it means "Sequence and Sequence-of types", defined in [X.680, ITU-T (2021), p14, Table 1 - Universal class tag assignments](./ref/T-REC-X.680-202102-I!!PDF-E.pdf) (ref: [X.680, ITU-T](https://www.itu.int/rec/T-REC-X.680-202102-I/en))


## Credit

- The code is based on [kirbi2hashcat, jarilaos](https://github.com/jarilaos/kirbi2hashcat/blob/master/kirbi2hashcat.py)
- Which was based on the Kerberoast script from Tim Medin to extract the Kerberos tickets from a kirbi file (https://github.com/nidem/kerberoast).
- And [kirbi2john.py](https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/kirbi2john.py)
- Which was then modified by Laox to use with hashcat
