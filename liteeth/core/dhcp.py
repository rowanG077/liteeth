#
# This file is part of LiteEth.
#
# Copyright (c) 2023 Florent Kermarrec <florent@enjoy-digital.fr>
# Copyright (c) 2023 LumiGuide Fietsdetectie B.V.
# Copyright (c) 2023 Rowan Goemans <goemansrowan@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

"""
DHCP

Minimal DHCP (IPV4) support for LiteEth.

Limitations/TODOs:
- No lease time parsing/support, user logic should consider it short (or known from server) and
issue a DHCP request regularly. Limitations is due to 32-bit data-path and parsing. Switching to a
8-bit data-path for DHCP options would allow supporting it more easily.
- Additional checks could be made on RX (see FIXMEs, but cost logic on FPGA).
- Define more DHCP constants and use them in the code.
"""

from migen import *

from litex.gen import *
from litex.gen.genlib.misc import WaitTimer

from liteeth.common import *

# DHCP Constants -----------------------------------------------------------------------------------

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

DHCP_MAX_PACKET_LENGTH     = 574
DHCP_FIXED_HEADER_LENGTH   = 240
DHCP_FIXED_DISCOVER_LENGTH = DHCP_FIXED_HEADER_LENGTH + 16
DHCP_FIXED_REQUEST_LENGTH  = DHCP_FIXED_HEADER_LENGTH + 28
DHCP_SERVER_NAME_LENGTH    = 64
DHCP_BOOT_FILE_NAME_LENGTH = 128

DHCP_TX_DISCOVER = 0b0
DHCP_TX_REQUEST  = 0b1

DHCP_RX_OFFER = 0b0
DHCP_RX_ACK   = 0b1

DHCP_OPTTYP_MESSAGE_TYPE          = 53
DHCP_OPTVAL_MESSAGE_TYPE_DISCOVER = 1
DHCP_OPTVAL_MESSAGE_TYPE_OFFER    = 2
DHCP_OPTVAL_MESSAGE_TYPE_REQUEST  = 3
DHCP_OPTVAL_MESSAGE_TYPE_ACK      = 5
DHCP_OPTTYP_REQ_IP_ADDRESS        = 50
DHCP_OPTTYP_SRV_IP_ADDRESS        = 54
DHCP_OPTTYP_LEASE_TIME            = 51
DHCP_OPTTYP_CLIENT_IDENTIFIER     = 61
DHCP_OPTTYP_PARAM_REQUEST_LIST    = 55
DHCP_OPTVAL_PARAM_SUBNET_MASK     = 3
DHCP_OPTVAL_PARAM_ROUTER          = 1
DHCP_OPTTYP_PAD                   = 0
DHCP_OPTTYP_END                   = 255

# DHCP TX ------------------------------------------------------------------------------------------

class LiteEthDHCPTX(LiteXModule):
    def __init__(self, udp_port):
        # Control/Status.
        self.start = Signal() # i
        self.done  = Signal() # o
        self.type  = Signal() # i

        # Parameters
        self.transaction_id     = Signal(32) # i
        self.mac_address        = Signal(48) # i
        self.server_ip_address  = Signal(32) # o (Only for Request).
        self.offered_ip_address = Signal(48) # o (Only for Request).

        # # #

        # Signals.
        # --------

        padding_len    = (8 + DHCP_SERVER_NAME_LENGTH + DHCP_BOOT_FILE_NAME_LENGTH) // 4
        count          = Signal(max=padding_len)
        longest_packet = max(DHCP_FIXED_DISCOVER_LENGTH, DHCP_FIXED_REQUEST_LENGTH) // 4
        length         = Signal(max=longest_packet)
        self.comb += Case(self.type, {
            DHCP_TX_DISCOVER : length.eq(DHCP_FIXED_DISCOVER_LENGTH // 4),
            DHCP_TX_REQUEST  : length.eq(DHCP_FIXED_REQUEST_LENGTH  // 4),
        })

        # Static Assign.
        # --------------
        self.comb += [
            udp_port.sink.src_port.eq(DHCP_CLIENT_PORT),
            udp_port.sink.dst_port.eq(DHCP_SERVER_PORT),
            udp_port.sink.ip_address.eq(convert_ip("255.255.255.255")),
            udp_port.sink.length.eq(length * 4),
            udp_port.sink.last_be.eq(0b1000), # 32-bit.
        ]

        # Common FSM.
        # -----------
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            If(self.start,
                NextState("HEADER")
            )
        )
        fsm.act("HEADER",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data[ 0: 8].eq(0x01), # Message Type: Boot Request (1).
            udp_port.sink.data[ 8:16].eq(0x01), # Hardware Type: Ethernet (1).
            udp_port.sink.data[16:24].eq(0x06), # Hardware Address Length: 6 bytes.
            udp_port.sink.data[24:32].eq(0x00), # Hops: 0.
            If(udp_port.sink.ready,
                NextState("TRANSACTION-ID")
            )
        )
        fsm.act("TRANSACTION-ID",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data.eq(self.transaction_id), # Transaction ID.
            If(udp_port.sink.ready,
                NextState("SECONDS-FLAGS")
            )
        )
        fsm.act("SECONDS-FLAGS",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data[ 0:16].eq(0x0000), # Seconds Elapsed: 0
            udp_port.sink.data[16:24].eq(0x8000), # Flags: Broadcast (0x8000)
            If(udp_port.sink.ready,
                NextState("CLIENT-IP-ADDRESS")
            )
        )
        fsm.act("CLIENT-IP-ADDRESS",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data.eq(0x00000000), # Client IP: 0.0.0.0.
            If(udp_port.sink.ready,
                NextState("YOUR-IP-ADDRESS")
            )
        )
        fsm.act("YOUR-IP-ADDRESS",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data.eq(0x00000000), # Your IP: 0.0.0.0.
            If(udp_port.sink.ready,
                NextState("SERVER-IP-ADDRESS")
            )
        )
        fsm.act("SERVER-IP-ADDRESS",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data.eq(0x00000000), # Server IP: 0.0.0.0.
            If(udp_port.sink.ready,
                NextState("GATEWAY-IP-ADDRESS")
            )
        )
        fsm.act("GATEWAY-IP-ADDRESS",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data.eq(0x00000000), # Gateway IP: 0.0.0.0.
            If(udp_port.sink.ready,
                NextState("CLIENT-MAC-ADDRESS-MSB")
            )
        )
        fsm.act("CLIENT-MAC-ADDRESS-MSB", # Client MAC address MSBs.
            udp_port.sink.valid.eq(1),
            udp_port.sink.data[ 0: 8].eq(self.mac_address[40:48]),
            udp_port.sink.data[ 8:16].eq(self.mac_address[32:40]),
            udp_port.sink.data[16:24].eq(self.mac_address[24:32]),
            udp_port.sink.data[24:32].eq(self.mac_address[16:24]),
            If(udp_port.sink.ready,
                NextState("CLIENT-MAC-ADDRESS-LSB")
            )
        )
        fsm.act("CLIENT-MAC-ADDRESS-LSB", # Client MAC address LSBs.
            udp_port.sink.valid.eq(1),
            udp_port.sink.data[ 0: 8].eq(self.mac_address[ 8:16]),
            udp_port.sink.data[ 8:16].eq(self.mac_address[ 0: 8]),
            udp_port.sink.data[16:24].eq(0x00),
            udp_port.sink.data[24:32].eq(0x00),
            If(udp_port.sink.ready,
                NextValue(count, padding_len - 1),
                NextState("PADDING")
            )
        )
        # Padding, includes:
        #  - Client MAC padding.
        #  - Server name (Unused).
        #  - BOOT-FILE-NAME (Unused).
        fsm.act("PADDING",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data.eq(0x00000000),
            If(udp_port.sink.ready,
                NextValue(count, count - 1),
                If(count == 0,
                    NextState("MAGIC-COOKIE")
                )
            )
        )
        fsm.act("MAGIC-COOKIE",
            udp_port.sink.valid.eq(1),
            udp_port.sink.data[ 0: 8].eq(0x63),
            udp_port.sink.data[ 8:16].eq(0x82),
            udp_port.sink.data[16:24].eq(0x53),
            udp_port.sink.data[24:32].eq(0x63),
            If(udp_port.sink.ready,
                NextState("OPTIONS-0")
            )
        )
        # Options.
        # --------
        fsm.act("OPTIONS-0",
            udp_port.sink.valid.eq(1),
            # DHCP Message Type: Discover.
            udp_port.sink.data[ 0: 8].eq(DHCP_OPTTYP_MESSAGE_TYPE),
            udp_port.sink.data[ 8:16].eq(0x01),
            If(self.type == DHCP_TX_DISCOVER,
                udp_port.sink.data[16:24].eq(DHCP_OPTVAL_MESSAGE_TYPE_DISCOVER),
            ).Elif(self.type == DHCP_TX_REQUEST,
                udp_port.sink.data[16:24].eq(DHCP_OPTVAL_MESSAGE_TYPE_REQUEST),
            ),
            # Client Identifier.
            udp_port.sink.data[24:32].eq(DHCP_OPTTYP_CLIENT_IDENTIFIER),
            If(udp_port.sink.ready,
                NextState("OPTIONS-1")
            )
        )
        fsm.act("OPTIONS-1",
            udp_port.sink.valid.eq(1),
            # Client Identifier.
            udp_port.sink.data[ 0: 8].eq(0x06),
            udp_port.sink.data[ 8:16].eq(self.mac_address[40:48]),
            udp_port.sink.data[16:24].eq(self.mac_address[32:40]),
            udp_port.sink.data[24:32].eq(self.mac_address[24:32]),
            If(udp_port.sink.ready,
                NextState("OPTIONS-2")
            )
        )
        fsm.act("OPTIONS-2",
            udp_port.sink.valid.eq(1),
            # Client Identifier.
            udp_port.sink.data[ 0: 8].eq(self.mac_address[16:24]),
            udp_port.sink.data[ 8:16].eq(self.mac_address[ 8:16]),
            udp_port.sink.data[16:24].eq(self.mac_address[ 0: 8]),
            # Parameter Request List: Subnet Mask, Router.
            udp_port.sink.data[24:32].eq(DHCP_OPTTYP_PARAM_REQUEST_LIST),
            If(udp_port.sink.ready,
                NextState("OPTIONS-3")
            )
        )
        fsm.act("OPTIONS-3",
            udp_port.sink.valid.eq(1),
            # Parameter Request List: Subnet Mask, Router.
            udp_port.sink.data[ 0: 8].eq(0x02),
            udp_port.sink.data[ 8:16].eq(DHCP_OPTVAL_PARAM_SUBNET_MASK),
            udp_port.sink.data[16:24].eq(DHCP_OPTVAL_PARAM_ROUTER),
            If(self.type == DHCP_TX_DISCOVER,
                udp_port.sink.last.eq(1),
                udp_port.sink.data[24:32].eq(DHCP_OPTTYP_END),
                If(udp_port.sink.ready, NextState("DONE"))
            ).Elif(self.type == DHCP_TX_REQUEST,
                udp_port.sink.last.eq(0),
                udp_port.sink.data[24:32].eq(DHCP_OPTTYP_REQ_IP_ADDRESS),
                If(udp_port.sink.ready, NextState("OPTIONS-4"))
            )
        )
        # These options are only transmitted for DHCP REQUEST.
        fsm.act("OPTIONS-4",
            udp_port.sink.valid.eq(1),
            # Requested IP Address.
            udp_port.sink.data[ 0: 8].eq(0x04),
            udp_port.sink.data[ 8:16].eq(self.offered_ip_address[24:32]),
            udp_port.sink.data[16:24].eq(self.offered_ip_address[16:24]),
            udp_port.sink.data[24:32].eq(self.offered_ip_address[ 8:16]),
            If(udp_port.sink.ready,
                NextState("OPTIONS-5")
            )
        )
        fsm.act("OPTIONS-5",
            udp_port.sink.valid.eq(1),
            # Requested IP Address.
            udp_port.sink.data[ 0: 8].eq(self.offered_ip_address[0:8]),
            # Server IP Address.
            udp_port.sink.data[ 8:16].eq(DHCP_OPTTYP_SRV_IP_ADDRESS),
            udp_port.sink.data[16:24].eq(0x04),
            udp_port.sink.data[24:32].eq(self.server_ip_address[24:32]),
            If(udp_port.sink.ready,
                NextState("OPTIONS-6")
            )
        )
        fsm.act("OPTIONS-6",
            udp_port.sink.last.eq(1),
            udp_port.sink.valid.eq(1),
            # Server IP Address.
            udp_port.sink.data[ 0: 8].eq(self.server_ip_address[16:24]),
            udp_port.sink.data[ 8:16].eq(self.server_ip_address[ 8:16]),
            udp_port.sink.data[16:24].eq(self.server_ip_address[ 0: 8]),
            # Client Identifier.
            udp_port.sink.data[24:32].eq(DHCP_OPTTYP_END),
            If(udp_port.sink.ready,
                NextState("DONE")
            )
        )
        # Done.
        # -----
        fsm.act("DONE",
            self.done.eq(1),
            NextState("IDLE")
        )

# DHCP Response/ACK --------------------------------------------------------------------------------

def eth_dhcp_opt_description(dw):
    assert(dw % 8 == 0)

    payload_layout = [("data", dw),]
    byte_count = dw // 8
    if byte_count > 1:
        payload_layout.append(("last_be", byte_count))

    return EndpointDescription(payload_layout)

# When downconverting from 32-bit to 8-bit we need to remove the last_be signal
# and set the last signal on the correct byte
class LiteEthDHCPOptDownConverter(LiteXModule):
    def __init__(self):
        self.source  = source = stream.Endpoint(eth_dhcp_opt_description(8))
        self.sink    = sink   = stream.Endpoint(eth_dhcp_opt_description(32))

        data         = Signal(32)
        byte_en      = Signal(4)
        latched_be   = Signal(4)
        latched_last = Signal()
        last_byte    = Signal()

        self.comb += [
            # @Florent: Is this necessary? Can we assume last_be is 0b1000 For non-last words?
            If(sink.last,
                byte_en.eq(sink.last_be),
            ).Else(
                byte_en.eq(0b1000),
            ),
            last_byte.eq(latched_be[0]),
            source.data.eq(data[0:8]),
            source.last.eq(last_byte & latched_last),
        ]

        self.fsm = fsm = FSM(reset_state="AWAIT-WORD")
        fsm.act("AWAIT-WORD",
            sink.ready.eq(1),
            source.valid.eq(0),
            NextValue(data, sink.data),
            NextValue(latched_last, sink.last),
            NextValue(latched_be, byte_en),
            If(sink.valid,
                NextState("COPY")
            )
        )

        fsm.act("COPY",
            sink.ready.eq(source.ready & last_byte),
            source.valid.eq(1),
            If(source.ready,
                NextValue(data, Cat(data[8:32], 0)),
                NextValue(latched_be, Cat(latched_be[1:4], 0)),
                If(last_byte,
                    NextValue(data, sink.data),
                    NextValue(latched_last, sink.last),
                    NextValue(latched_be, byte_en),
                    NextState("AWAIT-WORD"),
                    If(sink.valid,
                        NextState("COPY"),
                    )
                )
            )
        )


class LiteEthDHCPRxDebug(LiteXModule):
    def __init__(self, udp_port, fifo):
        # Static Assign.
        # --------------
        self.comb += [
            udp_port.sink.valid.eq(fifo.source.valid),
            udp_port.sink.data.eq(fifo.source.data),
            udp_port.sink.last.eq(fifo.source.last),
            fifo.source.ready.eq(udp_port.sink.ready),

            udp_port.sink.src_port.eq(8080),
            udp_port.sink.dst_port.eq(8080),
            udp_port.sink.ip_address.eq(convert_ip("255.255.255.255")),
            udp_port.sink.length.eq(1024),
            udp_port.sink.last_be.eq(0b1000), # 32-bit.
        ]

class LiteEthDHCPOptEngine(LiteXModule):
    def __init__(self):
        self.sink   = sink = stream.Endpoint(eth_udp_user_description(32))

        self.done              = Signal() # o
        self.error             = Signal() # o
        # DHCP Options outputs we care about
        # The gateway, subnet and lease_time are resetless
        # This is done because when Idling you don't
        # want to lose the old state
        self.type              = Signal()
        self.gateway           = Signal(32, reset_less=True)
        self.subnet_mask       = Signal(32, reset_less=True)
        self.lease_time        = Signal(32, reset_less=True)
        self.type_valid = type_valid             = Signal()
        self.gateway_valid = gateway_valid          = Signal()
        self.subnet_mask_valid = subnet_mask_valid      = Signal()
        self.lease_time_valid = lease_time_valid       = Signal()

        # this ensure we can hold the entire DHCP Options in FIFO
        depth     = (DHCP_MAX_PACKET_LENGTH - DHCP_FIXED_HEADER_LENGTH) // 4
        self.fifo = fifo = stream.SyncFIFO(eth_dhcp_opt_description(32), depth=depth, buffered=True)
        self.conv = conv = LiteEthDHCPOptDownConverter()

        self.comb += [
            self.sink.connect(fifo.sink, omit = {
                "error",
                "src_port",
                "dst_port",
                "ip_address",
                "length",
            }),
            fifo.source.connect(conv.sink),
        ]

        self.comb += conv.source.ready.eq(1)
        byte_stream = conv.source

        self.found_last = found_last = Signal()
        self.found_end =  found_end  = Signal()

        current_opt   = Signal(8)
        payload       = Signal(32)
        payload_valid = Signal()

        length        = Signal(8)
        payload_done  = Signal()

        self.comb += [
            self.done.eq(found_last | found_end),
            # self.error.eq(~(found_end & type_valid & lease_time_valid & gateway_valid & subnet_mask_valid)),
            self.error.eq(~found_end),
            payload_done.eq(length == 1)
        ]

        self.sync += If(byte_stream.valid,
            found_last.eq(found_last | byte_stream.last)
        )

        curr_state = Signal(3)

        self.dbg_o = Signal(32)

        self.comb += [
            self.dbg_o[ 0: 8].eq(byte_stream.data),
            self.dbg_o[ 8:16].eq(current_opt),
            self.dbg_o[16:19].eq(curr_state),
            self.dbg_o[19:20].eq(self.done),
            self.dbg_o[20:21].eq(self.error),
            self.dbg_o[21:22].eq(self.found_end),
            self.dbg_o[22:23].eq(self.found_last),
            self.dbg_o[23:24].eq(self.type_valid),
            self.dbg_o[24:25].eq(self.type),
            self.dbg_o[25:26].eq(self.gateway_valid),
            self.dbg_o[26:27].eq(self.lease_time_valid),
            self.dbg_o[27:28].eq(self.subnet_mask_valid),
            self.dbg_o[28:29].eq(payload_valid),
            self.dbg_o[29:30].eq(1),
            self.dbg_o[30:31].eq(1),
            self.dbg_o[31:32].eq(1),
        ]
        self.sync += If(payload_valid,
            Case(current_opt, {
                DHCP_OPTTYP_MESSAGE_TYPE: [
                    type_valid.eq(0),
                    If(payload[24:32] == DHCP_OPTVAL_MESSAGE_TYPE_OFFER,
                        type_valid.eq(1),
                        self.type.eq(DHCP_RX_OFFER),
                    ).Elif(payload[24:32] == DHCP_OPTVAL_MESSAGE_TYPE_ACK,
                        type_valid.eq(1),
                        self.type.eq(DHCP_RX_ACK),
                    )
                ],
                DHCP_OPTVAL_PARAM_SUBNET_MASK: [
                    subnet_mask_valid.eq(1),
                    self.subnet_mask[24:32].eq(payload[ 0: 8]),
                    self.subnet_mask[16:24].eq(payload[ 8:16]),
                    self.subnet_mask[ 8:16].eq(payload[16:24]),
                    self.subnet_mask[ 0: 8].eq(payload[24:32]),
                ],
                DHCP_OPTVAL_PARAM_ROUTER: [
                    gateway_valid.eq(1),
                    self.gateway[24:32].eq(payload[ 0: 8]),
                    self.gateway[16:24].eq(payload[ 8:16]),
                    self.gateway[ 8:16].eq(payload[16:24]),
                    self.gateway[ 0: 8].eq(payload[24:32]),
                ],
                DHCP_OPTTYP_LEASE_TIME: [
                    lease_time_valid.eq(1),
                    self.lease_time.eq(payload),
                ],
            }),
        )

        self.fsm = fsm = FSM(reset_state="HEADER")
        fsm.act("HEADER",
            curr_state.eq(0),
            NextValue(payload_valid, 0),
            NextValue(current_opt, byte_stream.data),
            If(byte_stream.valid,
                Case(byte_stream.data, {
                    DHCP_OPTTYP_PAD: [
                        NextState("HEADER"),
                    ],
                    DHCP_OPTTYP_END: [
                        NextValue(found_end, 1),
                        NextState("END"),
                    ],
                    "default": [
                        NextState("LEN"),
                    ]
                })
            )
        )
        fsm.act("LEN",
            curr_state.eq(1),
            If(byte_stream.valid,
                NextValue(length, byte_stream.data),
                NextValue(payload, 0b00000001_00000000_00000000_00000000),
                If(byte_stream.data == 0,
                    NextState("HEADER")
                ).Else(
                    NextState("PAYLOAD")
                )
            )
        )
        fsm.act("PAYLOAD",
            curr_state.eq(2),
            If(byte_stream.valid,
                NextValue(payload, Cat(payload[8:32], byte_stream.data)),
                NextValue(length, length - 1),
                NextValue(payload_valid, payload_done | payload[0]),
                If(payload_done,
                    NextState("HEADER")
                ).Elif(payload[0],
                    NextState("SKIP")
                )
            )
        )
        fsm.act("SKIP",
            curr_state.eq(3),
            If(byte_stream.valid,
                NextValue(length, length - 1),
                If(payload_done,
                    NextState("HEADER")
                )
            )
        )
        # Do nothing end state
        fsm.act("END", curr_state.eq(4), NextState("END"))

class LiteEthDHCPRX(LiteXModule):
    def __init__(self, udp_port, dbg_fifo=None):
        # Control/Status.
        self.present = Signal() # o
        self.capture = Signal() # i
        self.type    = Signal() # o
        self.error   = Signal() # o

        # Parameters
        self.transaction_id     = Signal(32) # i
        self.mac_address        = Signal(48) # i
        self.server_ip_address  = Signal(32) # o
        self.offered_ip_address = Signal(48) # o

        self.opt_engine  = opt_engine = ResetInserter()(LiteEthDHCPOptEngine())

        self.type        = opt_engine.type              # o
        self.gateway     = opt_engine.gateway           # o
        self.subnet_mask = opt_engine.subnet_mask       # o
        self.lease_time  = opt_engine.lease_time        # o

        # # #

        do_present = Signal()

        self.dbg = Signal(8)

        if dbg_fifo != None:
            dbg2 = Signal(8)
            dbg_trig = Signal()

            self.sync += dbg2.eq(self.dbg)
            self.comb += dbg_trig.eq(dbg2 != self.dbg)

            # self.comb += [
            #     dbg_fifo.sink.valid.eq(dbg_trig),
            #     dbg_fifo.sink.last.eq(True),
            #     dbg_fifo.sink.data.eq(Cat(self.dbg, self.dbg, self.dbg, self.dbg)),
            # ]

        # Common FSM.
        # -----------
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            NextValue(self.dbg, 0x1),

            NextValue(self.present, 0),
            NextValue(self.error, 0),
            NextValue(opt_engine.reset, 1),
            udp_port.source.ready.eq(0),

            If(udp_port.source.valid,
                NextValue(self.dbg, 0x2),
                If((udp_port.source.src_port == DHCP_SERVER_PORT) &
                   # Fixed header + message_type.
                   (udp_port.source.length > DHCP_FIXED_HEADER_LENGTH + 4),
                    NextValue(self.dbg, 0x3),
                    NextState("HEADER"),
                ).Else(
                    NextValue(self.dbg, 0x4),
                    NextValue(do_present, 0),
                    NextState("DROP"),
                )
            )
        )
        fsm.act("HEADER",
            NextValue(self.dbg, 0x10),
            NextValue(opt_engine.reset, 0),
            # FIXME: Add Check?
            udp_port.source.ready.eq(1),
            # drop if capture is not set
            If(~self.capture,
                NextValue(do_present, 0),
                NextState("DROP"),
            ).Elif(udp_port.source.valid,
                NextValue(self.dbg, 0x11),
                NextState("TRANSACTION-ID"),
            )
        )
        fsm.act("TRANSACTION-ID",
            NextValue(self.dbg, 0x20),
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                If(udp_port.source.data == self.transaction_id,
                    NextValue(self.dbg, 0x21),
                    NextState("SECONDS-FLAGS"),
                ).Else(
                    NextValue(self.dbg, 0x22),
                    NextValue(do_present, 0),
                    NextState("DROP"),
                )
            )
        )
        fsm.act("SECONDS-FLAGS",
            NextValue(self.dbg, 0x30),
            # FIXME: Add Check?
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                NextValue(self.dbg, 0x31),
                NextState("CLIENT-IP-ADDRESS"),
            )
        )
        fsm.act("CLIENT-IP-ADDRESS",
            NextValue(self.dbg, 0x40),
            # FIXME: Add Check?
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                NextValue(self.dbg, 0x41),
                NextState("YOUR-IP-ADDRESS"),
            )
        )
        fsm.act("YOUR-IP-ADDRESS",
            NextValue(self.dbg, 0x50),
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                NextValue(self.dbg, 0x51),
                NextValue(self.offered_ip_address[24:32], udp_port.source.data[ 0: 8]),
                NextValue(self.offered_ip_address[16:24], udp_port.source.data[ 8:16]),
                NextValue(self.offered_ip_address[ 8:16], udp_port.source.data[16:24]),
                NextValue(self.offered_ip_address[ 0: 8], udp_port.source.data[24:32]),
                NextState("SERVER-IP-ADDRESS"),
            ),
        )
        fsm.act("SERVER-IP-ADDRESS",
            NextValue(self.dbg, 0x60),
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                NextValue(self.dbg, 0x61),
                NextValue(self.server_ip_address[24:32], udp_port.source.data[ 0: 8]),
                NextValue(self.server_ip_address[16:24], udp_port.source.data[ 8:16]),
                NextValue(self.server_ip_address[ 8:16], udp_port.source.data[16:24]),
                NextValue(self.server_ip_address[ 0: 8], udp_port.source.data[24:32]),
                NextState("GATEWAY-IP-ADDRESS"),
            )
        )
        fsm.act("GATEWAY-IP-ADDRESS",
            NextValue(self.dbg, 0x70),
            # FIXME: Add Check?
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                NextValue(self.dbg, 0x71),
                NextState("CLIENT-MAC-ADDRESS-MSB"),
            )
        )
        fsm.act("CLIENT-MAC-ADDRESS-MSB", # Client MAC address MSBs.
            udp_port.source.ready.eq(1),
            NextValue(self.dbg, 0x80),
            If(udp_port.source.valid,
                If((udp_port.source.data[ 0: 8] == self.mac_address[40:48]) &
                   (udp_port.source.data[ 8:16] == self.mac_address[32:40]) &
                   (udp_port.source.data[16:24] == self.mac_address[24:32]) &
                   (udp_port.source.data[24:32] == self.mac_address[16:24]),
                    NextValue(self.dbg, 0x81),
                    NextState("CLIENT-MAC-ADDRESS-LSB"),
                ).Else(
                    NextValue(self.dbg, 0x82),
                    NextValue(do_present, 0),
                    NextState("DROP"),
                )
            )
        )
        fsm.act("CLIENT-MAC-ADDRESS-LSB", # Client MAC address LSBs.
            udp_port.source.ready.eq(1),
            NextValue(self.dbg, 0x90),

            If(udp_port.source.valid,
                If((udp_port.source.data[ 0: 8] == self.mac_address[ 8:16]) &
                   (udp_port.source.data[ 8:16] == self.mac_address[ 0: 8]),
                    NextValue(self.dbg, 0x91),
                    NextState("MAGIC-COOKIE"),
                ).Else(
                    NextValue(self.dbg, 0x92),
                    NextValue(do_present, 0),
                    NextState("DROP"),
                )
            )
        )
        fsm.act("MAGIC-COOKIE",
            NextValue(self.dbg, 0xA0),
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid,
                If((udp_port.source.data[ 0: 8] == 0x63) &
                   (udp_port.source.data[ 8:16] == 0x82) &
                   (udp_port.source.data[16:24] == 0x53) &
                   (udp_port.source.data[24:32] == 0x63),
                   NextState("OPTIONS"),
                   NextValue(self.dbg, 0xA1),
                )
            )
        )
        fsm.act("OPTIONS",
            udp_port.source.connect(opt_engine.sink),
            udp_port.source.ready.eq(1),
            NextValue(self.dbg, 0xB0),

            dbg_fifo.sink.valid.eq(opt_engine.conv.source.valid),
            dbg_fifo.sink.last.eq(0),
            dbg_fifo.sink.data.eq(opt_engine.dbg_o),

            If(udp_port.source.valid,
                # Drop the packet if OPTIONS engine cannot accept more
                # Any well formed DHCP packet should never overflow OPTIONS engine
                If(~opt_engine.sink.ready,
                    NextValue(self.error, 1),
                    If(udp_port.source.last,
                        NextValue(self.present, 1),
                        NextState("IDLE"),
                        NextValue(self.dbg, 0xB1),
                    ).Else(
                        NextValue(do_present, 1),
                        NextState("DROP"),
                        NextValue(self.dbg, 0xB2),
                    )
                ).Elif(udp_port.source.last,
                    NextState("AWAIT-OPT-ENGINE"),
                    NextValue(self.dbg, 0xB3),
                )
            )
        )
        # If we receive new data here it means a new packet has started and
        # we have to drop it
        prev_drop = Signal()
        drop = Signal()
        fsm.act("AWAIT-OPT-ENGINE",

            # dbg_fifo.sink.valid.eq(opt_engine.conv.source.valid),
            # dbg_fifo.sink.last.eq(opt_engine.conv.source.last),
            # dbg_fifo.sink.data.eq(opt_engine.conv.source.data),

            dbg_fifo.sink.valid.eq(opt_engine.conv.source.valid),
            dbg_fifo.sink.last.eq(opt_engine.done),
            dbg_fifo.sink.data.eq(opt_engine.dbg_o),

            NextValue(self.dbg, 0xC0),
            udp_port.source.ready.eq(1),
            drop.eq(~(udp_port.source.valid & udp_port.source.last) & (prev_drop | udp_port.source.valid)),
            NextValue(prev_drop, drop),
            If(opt_engine.done,
                NextValue(self.error, opt_engine.error),
                If(drop,
                    NextValue(do_present, 1),
                    NextState("DROP"),
                    NextValue(self.dbg, 0xC1),
                ).Else(
                    NextValue(self.present, 1),
                    NextState("IDLE"),
                    NextValue(self.dbg, 0xC2),
                )
            )
        )
        fsm.act("DROP",
            NextValue(self.dbg, 0xD0),
            udp_port.source.ready.eq(1),
            If(udp_port.source.valid & udp_port.source.last,
                NextValue(self.present, do_present),
                NextState("IDLE"),
                NextValue(self.dbg, 0xD1),
            )
        )

# DHCP ---------------------------------------------------------------------------------------------
class DHCPLeaseTimer(LiteXModule):
    def __init__(self, sys_clk_freq):
        self.load_lease = Signal()   # i
        self.lease_time = Signal(32) # i
        self.expired    = Signal()   # o

        # we run with 1% shorter seconds to ensure expiry
        # is always triggered before the real expiry
        sec_adjusted    = int(0.99 * sys_clk_freq)
        sec_counter     = Signal(max=sec_adjusted)
        prev_msb        = Signal()
        tick            = Signal()

        self.sync += [
            sec_counter.eq(sec_counter - 1),
            prev_msb.eq(sec_counter[-1])
        ]
        self.comb += tick.eq(prev_msb & ~sec_counter[-1])

        # We support a leasetime of max ~68 years
        # We can ignore the MSB of the leasetime this way
        # and use it to trigger expiry
        lease_time = Signal(32, reset=2**31-1)

        self.sync += If(self.load_lease,
            lease_time.eq(Cat(self.lease_time, 0))
        ).Elif(tick,
            lease_time.eq(lease_time - 1)
        )

        self.comb += self.expired.eq(lease_time[-1])

class LiteEthDHCP(LiteXModule):
    def __init__(self, udp_port, sys_clk_freq, timeout=1e0, udp_dbg_port = None):
        assert len(udp_port.sink.data) == 32 # Only supports 32-bit UDP port.

        self.udp_port = udp_port

        # Control/Status.
        self.start   = Signal() # i
        self.done    = Signal() # o
        self.timeout = Signal() # o

        # Parameters
        self.mac_address = Signal(48) # i
        self.ip_address  = Signal(48) # o

        # # #

        # Signals.
        transaction_id     = Signal(32)
        offered_ip_address = Signal(32)
        server_ip_address  = Signal(32)

        # DHCP TX.
        self.tx = tx = ResetInserter()(LiteEthDHCPTX(udp_port))
        self.comb += [
            tx.reset.eq(self.timeout),
            tx.mac_address.eq(self.mac_address),
            tx.transaction_id.eq(transaction_id),
        ]

        # DHCP RX.
        self.fifo = fifo = None
        if udp_dbg_port:
            self.fifo = fifo = stream.SyncFIFO(stream.EndpointDescription([("data", 32)]), depth=2048, buffered=True)
            self.dbg_rx = dbg_rx = LiteEthDHCPRxDebug(udp_dbg_port, fifo)

        self.rx = rx = ResetInserter()(LiteEthDHCPRX(udp_port, fifo))
        self.comb += [
            rx.reset.eq(self.timeout),
            rx.mac_address.eq(self.mac_address),
            rx.transaction_id.eq(transaction_id),
        ]

        # DHCP Timeout.
        self.timeout_timer = timeout_timer = WaitTimer(int(timeout*sys_clk_freq))
        self.comb += [
            timeout_timer.wait.eq(~self.done),
            self.timeout.eq(timeout_timer.done),
        ]

        # DHCP lease timer
        self.lease_timer = lease_timer = DHCPLeaseTimer(sys_clk_freq)

        # DHCP FSM.
        self.fsm = fsm = ResetInserter()(FSM(reset_state="IDLE"))
        self.comb += fsm.reset.eq(self.timeout)
        fsm.act("IDLE",
            self.done.eq(1),
            If(self.start | lease_timer.expired,
                NextValue(transaction_id, transaction_id + 1),
                NextState("SEND-DISCOVER")
            )
        )
        fsm.act("SEND-DISCOVER",
            tx.start.eq(1),
            tx.type.eq(DHCP_TX_DISCOVER),
            If(tx.done,
                NextState("RECEIVE-OFFER")
            )
        )
        fsm.act("RECEIVE-OFFER",
            rx.capture.eq(1),
            NextValue(offered_ip_address, rx.offered_ip_address),
            NextValue(server_ip_address,  rx.server_ip_address),
            If(rx.present & ~rx.error & (rx.type == DHCP_RX_OFFER),
                NextState("SEND-REQUEST")
            )
        )
        fsm.act("SEND-REQUEST",
            tx.start.eq(1),
            tx.type.eq(DHCP_TX_REQUEST),
            tx.offered_ip_address.eq(offered_ip_address),
            tx.server_ip_address.eq(server_ip_address),
            If(tx.done,
                NextState("RECEIVE-ACK")
            )
        )
        fsm.act("RECEIVE-ACK",
            rx.capture.eq(1),
            If(rx.present & ~rx.error & (rx.type == DHCP_RX_ACK),
                lease_timer.load_lease.eq(1),
                lease_timer.lease_time.eq(rx.lease_time),
                NextValue(self.ip_address, offered_ip_address),
                NextState("IDLE")
            )
        )
