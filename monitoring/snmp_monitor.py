"""
SNMP Managed Switch Monitoring Module for Physical Port-Level CRC/FCS Counters.
Queries RFC 1213 (IF-MIB) and RFC 1643 / 3635 (EtherLike-MIB dot3StatsFCSErrors).
Provides true physical-layer frame error visibility when OS NICs discard corrupted frames.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Standard MIB OIDs for Layer 2 Switch Port Monitoring
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"               # Port Description
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"         # 1 = Up, 2 = Down
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"          # Inbound frame errors
OID_IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"        # Inbound buffer drops
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"         # Outbound errors
OID_IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"       # Outbound drops
OID_DOT3_FCS_ERRORS = "1.3.6.1.2.1.10.7.2.1.3"     # True Hardware FCS/CRC errors
OID_DOT3_ALIGNMENT_ERRORS = "1.3.6.1.2.1.10.7.2.1.2" # Alignment/framing errors


class SnmpSwitchMonitor:
    """
    Connects to an Ethernet switch via SNMP v1/v2c to poll hardware counters.
    Calculates counter deltas and detects port resets.
    """

    def __init__(self, host: str, community: str = "public", port: int = 161,
                 if_index: int = 1, switch_name: str = "Switch"):
        self.host = host
        self.community = community
        self.port = port
        self.if_index = if_index
        self.switch_name = switch_name
        self.last_snapshot: Optional[Dict[str, Any]] = None
        self.total_fcs_delta = 0

    def test_connection(self) -> Dict[str, Any]:
        """Verify reachability and SNMP responsiveness of the target switch."""
        data = self.poll_port_counters()
        return {
            "reachable": data.get("success", False),
            "host": self.host,
            "port": self.port,
            "if_index": self.if_index,
            "error": data.get("error_msg")
        }

    def poll_port_counters(self) -> Dict[str, Any]:
        """
        Poll switch port statistics using PySNMP.
        Falls back cleanly with an informative message if the switch is offline or unsupported.
        """
        result = {
            "switch_name": self.switch_name,
            "host": self.host,
            "if_index": self.if_index,
            "success": False,
            "if_in_errors": 0,
            "if_in_discards": 0,
            "if_out_errors": 0,
            "if_out_discards": 0,
            "fcs_crc_errors": 0,
            "fcs_crc_delta": 0,
            "in_errors_delta": 0,
            "error_msg": None,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        try:
            # We attempt standard PySNMP synchronous get
            # PySNMP 7 supports high-level hlapi
            from pysnmp.hlapi.v1arch.asyncore import get_cmd, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
            
            # Target OIDs with specific interface index appended
            oids = [
                ObjectType(ObjectIdentity(f"{OID_IF_IN_ERRORS}.{self.if_index}")),
                ObjectType(ObjectIdentity(f"{OID_IF_IN_DISCARDS}.{self.if_index}")),
                ObjectType(ObjectIdentity(f"{OID_IF_OUT_ERRORS}.{self.if_index}")),
                ObjectType(ObjectIdentity(f"{OID_DOT3_FCS_ERRORS}.{self.if_index}"))
            ]

            # Execute query
            errorIndication, errorStatus, errorIndex, varBinds = next(
                get_cmd(
                    CommunityData(self.community, mpModel=1), # SNMPv2c
                    UdpTransportTarget((self.host, self.port), timeout=2.0, retries=1),
                    ContextData(),
                    *oids
                )
            )

            if errorIndication:
                result["error_msg"] = f"SNMP Connection Failed: {errorIndication}"
                return result
            elif errorStatus:
                result["error_msg"] = f"SNMP Error: {errorStatus.prettyPrint()} at {errorIndex}"
                return result

            # Parse returned values
            try:
                result["if_in_errors"] = int(varBinds[0][1])
                result["if_in_discards"] = int(varBinds[1][1])
                result["if_out_errors"] = int(varBinds[2][1])
                result["fcs_crc_errors"] = int(varBinds[3][1])
                result["success"] = True
            except (ValueError, TypeError, IndexError):
                result["success"] = True

        except Exception as e:
            # Fallback when pysnmp imports or asyncore bindings differ or switch is unreachable
            logger.debug("SNMP query to %s:%d failed: %s", self.host, self.port, e)
            result["error_msg"] = (
                f"Switch unreachable or SNMP disabled on {self.host}:{self.port}. "
                f"Ensure SNMPv2c service is active and community string matches."
            )
            return result

        # Calculate deltas
        if self.last_snapshot and result["success"]:
            prev_fcs = self.last_snapshot.get("fcs_crc_errors", 0)
            prev_errs = self.last_snapshot.get("if_in_errors", 0)

            # Check reset
            if result["fcs_crc_errors"] < prev_fcs or result["if_in_errors"] < prev_errs:
                result["fcs_crc_delta"] = result["fcs_crc_errors"]
                result["in_errors_delta"] = result["if_in_errors"]
            else:
                result["fcs_crc_delta"] = result["fcs_crc_errors"] - prev_fcs
                result["in_errors_delta"] = result["if_in_errors"] - prev_errs
        else:
            result["fcs_crc_delta"] = 0
            result["in_errors_delta"] = 0

        self.total_fcs_delta += result["fcs_crc_delta"]
        result["total_fcs_delta"] = self.total_fcs_delta
        self.last_snapshot = result
        return result
