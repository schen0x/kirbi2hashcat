#!/usr/bin/python3

# Add support for etype 17, 18
# Add references to some formats definition
# the 0x76 is KRB-CRED and 0x6d is TGS-REP
# [ASN1 Quick Reference](https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html)
# [RFC4120, The Kerberos Network Authentication Service (V5), Kerberos Application Tag Numbers](https://www.rfc-editor.org/rfc/rfc4120#page-96)
# [RFC4120, The Kerberos Network Authentication Service (V5), ASN.1 Module, TGS-REP](https://www.rfc-editor.org/rfc/rfc4120#page-126)
# [KERBEROS V5 ASN.1 Codec](https://cwiki.apache.org/confluence/display/DIRxASN1/Kerberos)

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
            print('-----')

            # .kirbi start with b'\x76', which is the "Tag" in "TLV" of ASN.1
            # 0x76: "KRB-CRED":
            # 0b01_1_10110: Class:application_Form:constructed_Tag:22; KRB-CRED ::= [APPLICATION 22] SEQUENCE {...}
            #
            # https://www.rfc-editor.org/rfc/rfc4120#page-92
            # KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
            #         pvno            [0] INTEGER (5),
            #         msg-type        [1] INTEGER (22),
            #         tickets         [2] SEQUENCE OF Ticket,
            #         enc-part        [3] EncryptedData -- EncKrbCredPart
            # }
            # https://www.rfc-editor.org/rfc/rfc4120#page-124
            # Ticket          ::= [APPLICATION 1] SEQUENCE {
            #         tkt-vno         [0] INTEGER (5),
            #         realm           [1] Realm,
            #         sname           [2] PrincipalName,
            #         enc-part        [3] EncryptedData -- EncTicketPart
            # }
            if bytes([data[0]]) == b'\x76':  # process .kirbi
                # 0.2.0 is the "Ticket"
                # 0.2.0.2 is the "Ticket"."PrincipalName"
                print(decoder.decode(data)[0][2][0][1]); # "Realm", "EXAMPLE.LOCAL"
                print(decoder.decode(data)[0][2][0][2][1][0]) # "PrincipalName".name-string[0], "MSSQLSvc"
                # print(decoder.decode(data)[0][2][0][2][1][1]) # "PrincipalName".name-string[1], "sql01.medin.local:1433"
                # rem dump
                bticket = data
                # etype: encryption type
                # [Kerberos Encryption Type Numbers](https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)
                etype = str(decoder.decode(bticket)[0][2][0][3][0])
                if etype not in ["23", "18", "17"]:
                    sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype);
                    exit(1);
                et = str(decoder.decode(bticket)[0][2][0][3][2]) # encrypted part

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

            # 0x6d: "TGS-REP" or "KDC-REP"
            # 0b01_1_01101: Class:application_Form:constructed_Tag:13; TGS-REP ::= [APPLICATION 13] KDC-REP; KDC-REP ::= SEQUENCE {...}
            #
            # KDC-REP         ::= SEQUENCE {
            #         pvno            [0] INTEGER (5),
            #         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
            #         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
            #                                 -- NOTE: not empty --,
            #         crealm          [3] Realm,
            #         cname           [4] PrincipalName,
            #         ticket          [5] Ticket,
            #         enc-part        [6] EncryptedData
            #                                 -- EncASRepPart or EncTGSRepPart,
            #                                 -- as appropriate
            # }
            # https://www.rfc-editor.org/rfc/rfc4120#page-126
            # https://cwiki.apache.org/confluence/display/DIRxASN1/Kerberos
            # https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/krb_structures/TGS_REP.cs
            #! Unfortunately this branch does not work properly because of 2 bugs in the "pyasn1.codec.ber" package and the kerberos implementation
            #! - Since 1. padata is OPTIONAL (it may be empty even though the spec says it should not)
            #! - And 2. the pyasn1 does not properly handle tag value (in this case 0xa0, 0xa1, 0xa3, 0xa4, 0xa5, where 0xa2 is absent),
            #!   i.e. the 0.4 should always be `cname`, however, when 0xa2 is absent, pyasn1 treat cname as 0.3 (despite the tag value 0xa4, the 4th)
            #!
            #! elif bytes([data[0]]) == b'\x6d':
            #!     # 0.5 is the "Ticket"
            #!     # 0.4 is the "PrincipalName"
            #!     print("realm")
            #!     print(decoder.decode(data)[0][3]); # "Realm"
            #!     print(decoder.decode(data)[0][4][1][0]) # "PrincipalName".name-string[0]
            #!     for ticket in data.strip().split(b'\n'):
            #!         bticket = bytes.fromhex(ticket)
            #!         print(decoder.decode(bticket)[0])
            #!         etype = str(decoder.decode(bticket)[0][5][3][0]) # "Ticket"."enc-part".etype
            #!         if etype != "23":
            #!             sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype)
            #!         et = str(decoder.decode(bticket)[0][4][3][2])
            #!         print("$krb5tgs$%s$" % etype + bytes(et[:16].encode('latin-1')).hex() + "$" + bytes(et[16:].encode('latin-1')).hex() + "\n")
