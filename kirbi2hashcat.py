#!/usr/bin/python3

# Add support for etype 17, 18
# Add references to some formats definition

# Dependency: pyasn1
# https://github.com/etingof/pyasn1/blob/master/pyasn1/codec/ber/decoder.py

# The original code which works on etype 23: https://github.com/jarilaos/kirbi2hashcat/blob/master/kirbi2hashcat.py
# Based on the Kerberoast script from Tim Medin to extract the Kerberos tickets
# from a kirbi file (https://github.com/nidem/kerberoast).
# https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/kirbi2john.py
# Modified by Laox to use with hashcat
from pyasn1.codec.ber import decoder
import sys

if __name__ == '__main__':
    m = "exported mimikatz kerberos tickets"

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <%s>\n" % (sys.argv[0], m))
        sys.exit(-1)

    for f in sys.argv[1:]:
        with open(f, 'rb') as fd:
            data = fd.read()
            print(decoder.decode(data)[0]) # The full decoded ASN.1 sequence, contains all info
            print('-----')
            # print(decoder.decode(data)[0][2][3])
            print('-----')
            print(decoder.decode(data)[0][2][0][1]); # tgsRealm, "EXAMPLE.LOCAL"
            print(decoder.decode(data)[0][2][0][2][1][0]) # "MSSQLSvc"
            print(decoder.decode(data)[0][2][0][2][1][1]) # "sql01.medin.local:1433"

            # .kirbi start with b'\x76'
            if bytes([data[0]]) == b'\x76':  # process .kirbi
                # rem dump
                bticket = data
                # etype: encryption type
                # [Kerberos Encryption Type Numbers](https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)
                etype = str(decoder.decode(bticket)[0][2][0][3][0])
                if etype not in ["23", "18", "17"]:
                    sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype);
                    exit(1);
                et = str(decoder.decode(bticket)[0][2][0][3][2])

                # GetUserSPNs.py can also decode etype 17 && 18, and has the print format
                # [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py#L194)
                if etype == "17": # etype 17 (AES128-CTS-HMAC-SHA1-96), 19600 Kerberos 5, TGS-REP; krb5tgs$17
                    pass # same as 18 (because the hashcat checksum for AES128 and 256 length are the same)

                if etype in ["18", "17"]: # etype 18 (AES256-CTS-HMAC-SHA1-96), 19700 Kerberos 5, TGS-REP; krb5tgs$18
                    tgsRealm = str(decoder.decode(bticket)[0][2][0][1])
                    spn = decoder.decode(data)[0][2][0][2][1][0] + '~' + decoder.decode(data)[0][2][0][2][1][1]
                    # Hashcat Accepted Ticket Format; the last 12 bytes are checksum; ref:
                    # https://github.com/GhostPack/Rubeus/issues/35
                    # https://github.com/hashcat/hashcat/blob/master/src/modules/module_19700.c#L140
                    print('$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (int(etype), 'sAMAccountName', tgsRealm, spn, bytes(et[-12:].encode('latin-1')).hex(), bytes(et[:-12:].encode('latin-1')).hex()))
                elif etype == "23": # etype 23 (rc4-hmac, deprecated); 13100 Kerberos 5, TGS-REP; krb5tgs$23
                    print("$krb5tgs$%s$" % etype + bytes(et[:16].encode('latin-1')).hex() + "$" + bytes(et[16:].encode('latin-1')).hex() + "\n")

            elif data[:2] == b'6d': # no idea what 0x6d means; can be wireshark; check the decoded bticket to figure out
                for ticket in data.strip().split(b'\n'):
                    bticket = bytes.fromhex(ticket)
                    print(decoder.decode(bticket)[0])
                    # etype = str(decoder.decode(ticket.decode('hex'))[0][4][3][0])
                    etype = str(decoder.decode(bticket)[0][4][3][0])
                    if etype != "23":
                        sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype)
                    # et = str(decoder.decode(ticket.decode('hex'))[0][4][3][2])
                    et = str(decoder.decode(bticket)[0][4][3][2])
                    print("$krb5tgs$%s$" % etype + bytes(et[:16].encode('latin-1')).hex() + "$" + bytes(et[16:].encode('latin-1')).hex() + "\n")
