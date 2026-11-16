
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr
import time
from collections import defaultdict, deque

log = core.getLogger()

class PortSecurity(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.macTable = {}
        self.blockedMacs = set()

        self.portTable = defaultdict(set)
        self.portHistory = defaultdict(deque)
        self.blockedPorts = set()
        self.maxHosts = 50
        self.timeWindow = 10
        self.portBlockTimes = {}
        self.blockDuration = 30

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if not packet.parsed:
            return

        ipPkt = packet.find('ipv4')
        if ipPkt is None:
            return
        srcMac = str(packet.src)
        srcIp = str(ipPkt.srcip)
        port = event.port
        currentTime = time.time()

        if port in self.blockedPorts:
            # remove old port blocks
            if currentTime - self.portBlockTimes[port] >= self.blockDuration:
                self.blockedPorts.remove(port)
                del self.portBlockTimes[port]
                log.info("Port %s unblocked", port)

            else:
                return

        # block attackers based on mac address
        if srcMac in self.blockedMacs:
            self._installDropRule(event, packet.src)
            return


        # remember mac with IP
        if srcMac not in self.macTable:
            self.macTable[srcMac] = srcIp

        elif self.macTable[srcMac] != srcIp:

            self.blockedMacs.add(srcMac)
            self._installDropRule(event, packet.src)
            return

        self.portTable[port].add((srcMac, srcIp))

        history = self.portHistory[port]
        history.append((currentTime, srcMac, srcIp))

        while history and currentTime - history[0][0] > self.timeWindow:
            history.popleft()

        uniqueHosts = set((mac, ip) for _, mac, ip in history)

        if len(uniqueHosts) > self.maxHosts:
            log.warning("MAC flooding detected on port %s. Blocking port.",port)

            self.blockedPorts.add(port)
            self.portBlockTimes[port] = currentTime
            self._installPortDropRule(port)

            return

    def _installDropRule(self, event, srcMac):
        msg = of.ofp_flow_mod()
        msg.match.dl_src = EthAddr(srcMac)
        msg.priority = 65535
        msg.idle_timeout = 0
        msg.hard_timeout = 0

        self.connection.send(msg)


        log.info("Installed drop rule for MAC %s", srcMac)

    def _installPortDropRule(self, port):
        msg = of.ofp_flow_mod()
        msg.match.in_port = port
        msg.priority = 65535
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        self.connection.send(msg)

        log.warning("Installed drop rule for port %s", port)


def launch():
    def startSwitch(event):
        log.debug("Controlling %s" % (event.connection,))
        PortSecurity(event.connection)

    core.openflow.addListenerByName("ConnectionUp", startSwitch)
