
def getIcmpErrorMessage(icmpType, icmpCode):
    errorMessages = {
        1: 'Unassigned',
        2: 'Unassigned',
        3: 'Destination Unreachable',
        4: 'Source Quench (Deprecated)',
        5: 'Redirect',
        6: 'Alternate Host Address (Deprecated)',
        7: 'Unassigned',
        8: 'Echo',
        9: 'Router Advertisement',
        10: 'Router Solicitation',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp',
        14: 'Timestamp Reply',
        15: 'Information Request (Deprecated)',
        16: 'Information Reply (Deprecated)',
        17: 'Address Mask Request (Deprecated)',
        18: 'Address Mask Reply (Deprecated)',
        19: 'Reserved (for Security)',
        range(20, 30): 'Reserved (for Robustness Experiment)',
        30: 'Traceroute (Deprecated)',
        31: 'Datagram Conversion Error (Deprecated)',
        32: 'Mobile Host Redirect (Deprecated)',
        33: 'IPv6 Where-Are-You (Deprecated)',
        34: 'IPv6 I-Am-Here (Deprecated)',
        35: 'Mobile Registration Request (Deprecated)',
        36: 'Mobile Registration Reply (Deprecated)',
        37: 'Domain Name Request (Deprecated)',
        38: 'Domain Name Reply (Deprecated)',
        39: 'SKIP (Deprecated)',
        40: 'Photuris',
        41: 'ICMP messages utilized by experimental\n        mobility protocols such as Seamoby',
        42: 'Extended Echo Request',
        43: 'Extended Echo Reply',
        range(44, 253): 'Unassigned',
        253: 'RFC3692-style Experiment 1',
        254: 'RFC3692-style Experiment 2',
        255: 'Reserved'
    }

    type3Codes = {
        0: 'Net Unreachable',
        1: 'Host Unreachable',
        2: 'Protocol Unreachable',
        3: 'Port Unreachable',
        4: "Fragmentation Needed and Don't Fragment was Set",
        5: 'Source Route Failed',
        6: 'Destination Network Unknown',
        7: 'Destination Host Unknown',
        8: 'Source Host Isolated',
        9: 'Communication with Destination Network is Administratively Prohibited',
        10: 'Communication with Destination Host is Administratively Prohibited',
        11: 'Destination Network Unreachable for Type of Service',
        12: 'Destination Host Unreachable for Type of Service',
        13: 'Communication Administratively Prohibited',
        14: 'Host Precedence Violation',
        15: 'Precedence cutoff in effect'
    }

    type11Codes = {
        0: 'Time to Live exceeded in Transit',
        1: 'Fragment Reassembly Time Exceeded',
    }

    if icmpType == 3:
        return f"Error Type = {icmpType} Error Name = {errorMessages[icmpType]} Code = {icmpCode} Code Description = {type3Codes[icmpCode]}"

    if icmpType == 11:
        return f"Error Type = {icmpType} Error Name = {errorMessages[icmpType]} Code = {icmpCode} Code Description= {type11Codes[icmpCode]}"

    return f"Error Type = {icmpType} Error Name = {errorMessages[icmpType]} Code = {icmpCode}"

error = getIcmpErrorMessage(3, 8)
print(error)