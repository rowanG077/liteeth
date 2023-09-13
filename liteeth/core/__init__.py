#
# This file is part of LiteEth.
#
# Copyright (c) 2015-2020 Florent Kermarrec <florent@enjoy-digital.fr>
# Copyright (c) 2023 LumiGuide Fietsdetectie B.V. <goemansrowan@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from liteeth.common    import *
from liteeth.mac       import LiteEthMAC
from liteeth.core.arp  import LiteEthARP
from liteeth.core.ip   import LiteEthIP
from liteeth.core.udp  import LiteEthUDP
from liteeth.core.icmp import LiteEthICMP

# IP Core ------------------------------------------------------------------------------------------

class LiteEthIPCore(Module, AutoCSR):
    def __init__(self, phy, mac_address, ip_address, clk_freq, dw=8,
        with_icmp         = True,
        with_ip_broadcast = True,
        with_sys_datapath = False,
        gateway           = None,
        netaddress        = None,
        netmask           = None,
        tx_cdc_depth      = 32,
        tx_cdc_buffered   = True,
        rx_cdc_depth      = 32,
        rx_cdc_buffered   = True,
    ):
        # Parameters.
        # -----------
        ip_address = convert_ip(ip_address)

        # MAC.
        # ----
        self.submodules.mac = LiteEthMAC(
            phy               = phy,
            dw                = dw,
            interface         = "crossbar",
            with_preamble_crc = True,
            with_sys_datapath = with_sys_datapath,
            tx_cdc_depth      = tx_cdc_depth,
            tx_cdc_buffered   = tx_cdc_buffered,
            rx_cdc_depth      = rx_cdc_depth,
            rx_cdc_buffered   = rx_cdc_buffered
        )

        # ARP.
        # ----
        self.submodules.arp = LiteEthARP(
            mac         = self.mac,
            mac_address = mac_address,
            ip_address  = ip_address,
            clk_freq    = clk_freq,
            dw          = dw,
        )

        # IP.
        # ---
        self.submodules.ip  = LiteEthIP(
            mac            = self.mac,
            mac_address    = mac_address,
            ip_address     = ip_address,
            arp_table      = self.arp.table,
            gateway        = gateway,
            netaddress     = netaddress,
            netmask        = netmask,
            with_broadcast = with_ip_broadcast,
            dw             = dw,
        )
        # ICMP (Optional).
        # ----------------
        if with_icmp:
            self.submodules.icmp = LiteEthICMP(
                ip         = self.ip,
                ip_address = ip_address,
                dw         = dw,
            )

# UDP IP Core --------------------------------------------------------------------------------------

class LiteEthUDPIPCore(LiteEthIPCore):
    def __init__(self, phy, mac_address, ip_address, clk_freq, dw=8,
        with_icmp         = True,
        with_dhcp         = False,
        with_ip_broadcast = True,
        with_sys_datapath = False,
        gateway           = None,
        netaddress        = None,
        netmask           = None,
        tx_cdc_depth      = 32,
        tx_cdc_buffered   = True,
        rx_cdc_depth      = 32,
        rx_cdc_buffered   = True,
    ):
        # Ensure either IP is external or DHCP is used
        assert((ip_address is None) == with_dhcp)

        # Parameters.
        # -----------
        if ip_address is not None:
            ip_address = convert_ip(ip_address)
        else:
            ip_address = Signal(32)

        # Core: MAC + ARP + IP + (ICMP).
        # ------------------------------
        LiteEthIPCore.__init__(self,
            phy               = phy,
            mac_address       = mac_address,
            ip_address        = ip_address,
            clk_freq          = clk_freq,
            with_icmp         = with_icmp,
            dw                = dw,
            with_ip_broadcast = with_ip_broadcast,
            with_sys_datapath = with_sys_datapath,
            gateway           = gateway,
            netaddress        = netaddress,
            netmask           = netmask,
            tx_cdc_depth      = tx_cdc_depth,
            tx_cdc_buffered   = tx_cdc_buffered,
            rx_cdc_depth      = rx_cdc_depth,
            rx_cdc_buffered   = rx_cdc_buffered,
        )
        # UDP + (DHCP).
        # -------------
        self.submodules.udp = LiteEthUDP(
            ip          = self.ip,
            mac_address = mac_address,
            ip_address  = ip_address,
            clk_freq    = clk_freq,
            with_dhcp   = with_dhcp,
            dw          = dw,
        )
