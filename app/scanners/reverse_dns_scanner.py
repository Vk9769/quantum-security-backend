import socket
import ipaddress
import logging

logger = logging.getLogger("ReverseDNS")


def reverse_dns(prefix):

    discovered = []

    net = ipaddress.ip_network(prefix)

    for ip in net.hosts():

        try:

            host = socket.gethostbyaddr(str(ip))[0]

            discovered.append(host)

        except:
            pass

    return discovered