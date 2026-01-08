"""
DNS over QUIC Resolver Module
Implements DNS resolution using DNS over QUIC protocol to avoid system DNS.
"""

import asyncio
import struct
import logging
from typing import Optional, List
from dataclasses import dataclass

try:
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.asyncio.protocol import QuicConnectionProtocol
except ImportError:
    # aioquic is optional, will be added to requirements
    pass


logger = logging.getLogger('BunnyTunnel.DNSResolver')


@dataclass
class DNSQuery:
    """Represents a DNS query."""
    domain: str
    qtype: int = 1  # A record
    qclass: int = 1  # IN class


class DNSOverQUICResolver:
    """
    DNS over QUIC resolver.
    Uses dns.adguard-dns.com as the DNS server.
    """
    
    DEFAULT_SERVER = "dns.adguard-dns.com"
    DEFAULT_PORT = 853
    
    def __init__(
        self,
        server: str = DEFAULT_SERVER,
        port: int = DEFAULT_PORT,
        timeout: float = 5.0
    ):
        """
        Initialize DNS over QUIC resolver.
        
        Args:
            server: DNS server hostname
            port: DNS server port (default 853 for DoQ)
            timeout: Query timeout in seconds
        """
        self.server = server
        self.port = port
        self.timeout = timeout
        self._cache: dict[str, tuple[List[str], float]] = {}
        self._cache_ttl = 300.0  # 5 minutes
    
    def _build_dns_query(self, query: DNSQuery) -> bytes:
        """
        Build DNS query packet.
        
        Args:
            query: DNS query
            
        Returns:
            DNS query packet bytes
        """
        # DNS header
        transaction_id = 0x1234
        flags = 0x0100  # Standard query, recursion desired
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0
        
        packet = struct.pack(
            '!HHHHHH',
            transaction_id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount
        )
        
        # Question section
        for label in query.domain.split('.'):
            packet += struct.pack('!B', len(label))
            packet += label.encode('ascii')
        packet += b'\x00'  # End of domain name
        
        packet += struct.pack('!HH', query.qtype, query.qclass)
        
        return packet
    
    def _parse_dns_response(self, response: bytes) -> List[str]:
        """
        Parse DNS response packet.
        
        Args:
            response: DNS response packet bytes
            
        Returns:
            List of IP addresses
        """
        if len(response) < 12:
            raise ValueError("DNS response too short")
        
        # Parse header
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            '!HHHHHH',
            response[:12]
        )
        
        # Check response code
        rcode = flags & 0x000F
        if rcode != 0:
            raise ValueError(f"DNS query failed with rcode {rcode}")
        
        # Skip question section
        offset = 12
        for _ in range(qdcount):
            # Skip domain name
            while offset < len(response):
                length = response[offset]
                if length == 0:
                    offset += 1
                    break
                elif (length & 0xC0) == 0xC0:
                    # Compressed name
                    offset += 2
                    break
                else:
                    offset += 1 + length
            
            # Skip qtype and qclass
            offset += 4
        
        # Parse answer section
        addresses = []
        for _ in range(ancount):
            # Skip name
            while offset < len(response):
                length = response[offset]
                if length == 0:
                    offset += 1
                    break
                elif (length & 0xC0) == 0xC0:
                    # Compressed name
                    offset += 2
                    break
                else:
                    offset += 1 + length
            
            if offset + 10 > len(response):
                break
            
            # Parse type, class, ttl, rdlength
            rtype, rclass, ttl, rdlength = struct.unpack(
                '!HHIH',
                response[offset:offset + 10]
            )
            offset += 10
            
            # Parse rdata
            if rtype == 1 and rdlength == 4:  # A record
                ip = '.'.join(str(b) for b in response[offset:offset + 4])
                addresses.append(ip)
            
            offset += rdlength
        
        return addresses
    
    async def resolve(self, domain: str) -> Optional[str]:
        """
        Resolve domain name to IP address using DNS over QUIC.
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        # Check cache
        import time
        now = time.time()
        if domain in self._cache:
            addresses, timestamp = self._cache[domain]
            if now - timestamp < self._cache_ttl:
                return addresses[0] if addresses else None
        
        try:
            # Build DNS query
            query = DNSQuery(domain=domain)
            query_packet = self._build_dns_query(query)
            
            # Configure QUIC
            configuration = QuicConfiguration(
                is_client=True,
                alpn_protocols=["doq"],
            )
            configuration.verify_mode = False  # For simplicity, disable cert verification
            
            # Connect to DNS server
            async with connect(
                self.server,
                self.port,
                configuration=configuration,
                create_protocol=QuicConnectionProtocol,
            ) as protocol:
                # Send DNS query
                stream_id = protocol._quic.get_next_available_stream_id()
                protocol._quic.send_stream_data(stream_id, query_packet, end_stream=True)
                
                # Receive response
                response_data = b''
                async def receive():
                    nonlocal response_data
                    for event in protocol._quic._events:
                        if hasattr(event, 'data'):
                            response_data += event.data
                
                await asyncio.wait_for(receive(), timeout=self.timeout)
                
                # Parse response
                addresses = self._parse_dns_response(response_data)
                
                # Cache result
                self._cache[domain] = (addresses, now)
                
                return addresses[0] if addresses else None
                
        except Exception as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            return None
    
    async def resolve_with_fallback(self, domain: str) -> Optional[str]:
        """
        Resolve domain with fallback to system DNS.
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            IP address or None
        """
        # Try DNS over QUIC first
        ip = await self.resolve(domain)
        if ip:
            return ip
        
        # Fallback to system DNS
        try:
            logger.warning(f"Falling back to system DNS for {domain}")
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None)
            if result:
                return result[0][4][0]
        except Exception as e:
            logger.error(f"System DNS resolution failed for {domain}: {e}")
        
        return None
    
    def clear_cache(self) -> None:
        """Clear DNS cache."""
        self._cache.clear()
