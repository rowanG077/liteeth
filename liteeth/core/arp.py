#
# This file is part of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr>
# SPDX-License-Identifier: BSD-2-Clause

from operator import xor

from litex.gen import *
from litex.gen.genlib.misc import WaitTimer

from liteeth.common import *
from liteeth.packet import Depacketizer, Packetizer

# ARP Layouts --------------------------------------------------------------------------------------

_arp_table_layout = [
        ("reply",        1),
        ("request",      1),
        ("ip_address",  32),
        ("mac_address", 48)
    ]

# ARP TX -------------------------------------------------------------------------------------------

class LiteEthARPPacketizer(Packetizer):
    def __init__(self, dw=8):
        Packetizer.__init__(self,
            eth_arp_description(dw),
            eth_mac_description(dw),
            arp_header
        )


class LiteEthARPTX(LiteXModule):
    def __init__(self, mac_address, ip_address, dw=8):
        self.sink   = sink   = stream.Endpoint(_arp_table_layout)
        self.source = source = stream.Endpoint(eth_mac_description(dw))

        # # #

        packet_length = max(arp_header.length, arp_min_length)
        packet_words  = packet_length//(dw//8)
        counter       = Signal(max=packet_words, reset_less=True)

        self.packetizer = packetizer = LiteEthARPPacketizer(dw)

        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            NextValue(counter, 0),
            If(sink.valid,
                NextState("SEND")
            )
        )
        self.comb += [
            packetizer.sink.last.eq(counter == (packet_words - 1)),
            If(packetizer.sink.last,
                packetizer.sink.last_be.eq(
                    1 if len(packetizer.sink.last_be) == 1 else 2**(packet_length % (dw // 8) - 1)
                ),
            ),
            packetizer.sink.hwtype.eq(arp_hwtype_ethernet),
            packetizer.sink.proto.eq(arp_proto_ip),
            packetizer.sink.hwsize.eq(6),
            packetizer.sink.protosize.eq(4),
            packetizer.sink.sender_mac.eq(mac_address),
            packetizer.sink.sender_ip.eq(ip_address),
            packetizer.sink.target_ip.eq(sink.ip_address),
            If(sink.reply,
                packetizer.sink.opcode.eq(arp_opcode_reply),
                packetizer.sink.target_mac.eq(sink.mac_address),
            ).Elif(sink.request,
                packetizer.sink.opcode.eq(arp_opcode_request),
                packetizer.sink.target_mac.eq(bcast_mac_address),
            )
        ]
        self.comb += [
            packetizer.source.connect(source, omit={"valid", "ready"}),
            source.target_mac.eq(packetizer.sink.target_mac),
            source.sender_mac.eq(mac_address),
            source.ethernet_type.eq(ethernet_type_arp),
        ]
        fsm.act("SEND",
            packetizer.sink.valid.eq(1),
            packetizer.source.connect(source, keep={"valid", "ready"}),
            If(source.valid & source.ready,
                NextValue(counter, counter + 1),
                If(source.last,
                    sink.ready.eq(1),
                    NextState("IDLE")
                )
            )
        )

# ARP RX -------------------------------------------------------------------------------------------

class LiteEthARPDepacketizer(Depacketizer):
    def __init__(self, dw=8):
        Depacketizer.__init__(self,
            eth_mac_description(dw),
            eth_arp_description(dw),
            arp_header)


class LiteEthARPRX(LiteXModule):
    def __init__(self, mac_address, ip_address, dw=8):
        self.sink   = sink   = stream.Endpoint(eth_mac_description(dw))
        self.source = source = stream.Endpoint(_arp_table_layout)

        # # #s

        self.depacketizer = depacketizer = LiteEthARPDepacketizer(dw)
        self.comb += sink.connect(depacketizer.sink)

        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            depacketizer.source.ready.eq(1),
            If(depacketizer.source.valid,
                depacketizer.source.ready.eq(0),
                NextState("CHECK")
            )
        )
        valid = Signal(reset_less=True)
        self.sync += valid.eq(
            depacketizer.source.valid &
            (depacketizer.source.hwtype == arp_hwtype_ethernet) &
            (depacketizer.source.proto == arp_proto_ip) &
            (depacketizer.source.hwsize == 6) &
            (depacketizer.source.protosize == 4) &
            (depacketizer.source.target_ip == ip_address)
        )
        reply = Signal()
        request = Signal()
        self.comb += Case(depacketizer.source.opcode, {
            arp_opcode_request: [request.eq(1)],
            arp_opcode_reply:   [reply.eq(1)],
            "default":          []
            })
        self.comb += [
            source.ip_address.eq(depacketizer.source.sender_ip),
            source.mac_address.eq(depacketizer.source.sender_mac)
        ]
        fsm.act("CHECK",
            If(valid,
                source.valid.eq(1),
                source.reply.eq(reply),
                source.request.eq(request)
            ),
            NextState("TERMINATE")
        ),
        fsm.act("TERMINATE",
            depacketizer.source.ready.eq(1),
            If(depacketizer.source.valid & depacketizer.source.last,
                NextState("IDLE")
            )
        )

# ARP Table ----------------------------------------------------------------------------------------
class LiteEthARPHashTable(LiteXModule):
    def __init__(self, clk_freq):
        entries = 16

        operation_done = Signal(reset_less=True)
        operation_ip = Signal(32, reset_less=True)

        lookup_request = Signal()
        lookup_found = Signal(reset_less=True)
        lookup_mac = Signal(48, reset_less=True)

        insert_request = Signal()
        insert_mac = Signal(48, reset_less=True)

        # TODO: We xor all nibbles together of the IP to obtain the hash
        #       It's probably better to to a proper hashing using some kind of LFSR
        #       in the future
        lookup_ptr = Signal(4, reset_less=True)
        self.sync += [
            lookup_ptr[0].eq(xor(xor(operation_ip[0], operation_ip[4]), xor(operation_ip[8], operation_ip[12]))),
            lookup_ptr[1].eq(xor(xor(operation_ip[1], operation_ip[5]), xor(operation_ip[9], operation_ip[13]))),
            lookup_ptr[2].eq(xor(xor(operation_ip[2], operation_ip[6]), xor(operation_ip[10], operation_ip[14]))),
            lookup_ptr[3].eq(xor(xor(operation_ip[3], operation_ip[7]), xor(operation_ip[11], operation_ip[15]))),
        ]

        # Hold 2 bit valid counter + IP + mac address back to back
        table_mem = Memory(2 + 32 + 48, entries)
        table_port = table_mem.get_port(write_capable=True)
        self.specials += table_mem, table_port
        init_expiry = Constant(3, bits_sign=(2, False))

        # Every second go through an entry in the table and decrement valid counter
        # Since valid counter has 2 bits it takes 3 decrements to reach 0.
        # Every entry is hit every 16 seconds. So an entry is valid for 48 seconds
        expiry_timer = WaitTimer(clk_freq)
        self.submodules += expiry_timer

        expiry_ptr = Signal(bits_for(entries), reset_less = True)

        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            lookup_mac.eq(table_port.dat_r[34:82]),
            NextValue(operation_done, 0),
            NextValue(expiry_timer.wait, 1),
            If(expiry_timer.done,
                table_port.adr.eq(expiry_ptr),
                NextState("DECREMENT_COUNTER")
            )
            .Elif(lookup_request,
                NextState("DO_LOOKUP")
            )
            .Elif(insert_request,
                NextState("DO_INSERT")
            )
        )

        fsm.act("DECREMENT_COUNTER",
            NextValue(expiry_timer.wait, 0),
            table_port.adr.eq(expiry_ptr),
            If(table_port.dat_r[0:2] != 0,
                table_port.we.eq(1),
                table_port.dat_w.eq(Cat(table_port.dat_r[0:2] - 1, table_port.dat_r[3:]))
            ),
            NextValue(expiry_ptr, expiry_ptr + 1),
            NextState("IDLE")
        )

        fsm.act("DO_LOOKUP",
            table_port.adr.eq(lookup_ptr),
            NextState("TEST_IP")
        )
        fsm.act("TEST_IP",
            table_port.adr.eq(lookup_ptr),
            NextValue(lookup_found, (table_port.dat_r[0:2] != 0) & (table_port.dat_r[2:34] == operation_ip)),
            NextValue(operation_done, 1),
            NextState("IDLE")
        )

        fsm.act("DO_INSERT",
            table_port.we.eq(1),
            table_port.adr.eq(lookup_ptr),
            table_port.dat_w.eq(Cat(init_expiry, operation_ip, insert_mac)),
            NextValue(operation_done, 1),
        )

class LiteEthARPTable(LiteXModule):
    def __init__(self, clk_freq, max_requests=8):
        self.sink   = sink   = stream.Endpoint(_arp_table_layout)  # from arp_rx
        self.source = source = stream.Endpoint(_arp_table_layout)  # to arp_tx

        # Request/Response interface
        self.request  = request  = stream.Endpoint(arp_table_request_layout)
        self.response = response = stream.Endpoint(arp_table_response_layout)

        # # #

        request_pending     = Signal()
        request_pending_clr = Signal()
        request_pending_set = Signal()
        self.sync += \
            If(request_pending_clr,
                request_pending.eq(0)
            ).Elif(request_pending_set,
                request_pending.eq(1)
            )

        request_ip_address = Signal(32, reset_less=True)
        self.sync += \
            If(request.valid,
                request_ip_address.eq(request.ip_address)
            )

        rx_ip_address = Signal(32, reset_less=True)
        rx_mac_address = Signal(48, reset_less=True)
        self.sync += \
            If(sink.valid,
                rx_ip_address.eq(sink.ip_address),
                rx_mac_address.eq(sink.mac_address)
            )

        request_timer = WaitTimer(clk_freq//10)
        self.submodules += request_timer
        request_counter       = Signal(max=max_requests)
        request_counter_reset = Signal()
        request_counter_ce    = Signal()
        self.sync += \
            If(request_counter_reset,
                request_counter.eq(0)
            ).Elif(request_counter_ce,
                request_counter.eq(request_counter + 1)
            )
        self.comb += request_timer.wait.eq(request_pending & ~request_counter_ce)

        # hash table
        hash_table = LiteEthARPHashTable(clk_freq)
        self.submodules += hash_table

        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            # Note: for simplicicy, if ARP table is busy response from arp_rx
            # is lost. This is compensated by the protocol (retries)
            If(sink.valid & sink.request,
                NextState("SEND_REPLY")
            ).Elif(sink.valid & sink.reply & request_pending,
                NextState("UPDATE_TABLE"),
            ).Elif(request_counter == max_requests-1,
                NextState("PRESENT_RESPONSE")
            ).Elif(request.valid | (request_pending & request_timer.done),
                NextState("CHECK_TABLE")
            )
        )
        fsm.act("SEND_REPLY",
            source.valid.eq(1),
            source.reply.eq(1),
            source.ip_address.eq(rx_ip_address),
            source.mac_address.eq(rx_mac_address),
            If(source.ready,
                NextState("IDLE")
            )
        )
        fsm.act("UPDATE_TABLE",
            request_pending_clr.eq(1),
            hash_table.insert_request.eq(1),
            hash_table.lookup_request.eq(0),
            hash_table.operation_ip.eq(rx_mac_address),
            hash_table.insert_mac.eq(rx_ip_address),
            If(hash_table.operation_done,
                NextState("CHECK_TABLE")
            )
        )

        fsm.act("CHECK_TABLE",
            hash_table.insert_request.eq(0),
            hash_table.lookup_request.eq(1),
            hash_table.operation_ip.eq(request_ip_address),
            If(hash_table.operation_done & hash_table.lookup_found,
                request_ip_address_reset.eq(1),
                NextState("PRESENT_RESPONSE"),
            )
            .Elif(hash_table.operation_done,
                NextState("PRESENT_RESPONSE"),
            )

            If(cached_valid,
                If(request_ip_address == cached_ip_address,
                    request_ip_address_reset.eq(1),
                    NextState("PRESENT_RESPONSE"),
                ).Elif(request.ip_address == cached_ip_address,
                    request.ready.eq(request.valid),
                    NextState("PRESENT_RESPONSE"),
                ).Else(
                    request_ip_address_update.eq(request.valid),
                    NextState("SEND_REQUEST")
                )
            ).Else(
                request_ip_address_update.eq(request.valid),
                NextState("SEND_REQUEST")
            )
        )
        fsm.act("SEND_REQUEST",
            source.valid.eq(1),
            source.request.eq(1),
            source.ip_address.eq(request_ip_address),
            If(source.ready,
                request_counter_reset.eq(request.valid),
                request_counter_ce.eq(1),
                request_pending_set.eq(1),
                request.ready.eq(1),
                NextState("IDLE")
            )
        )
        self.comb += [
            If(request_counter == max_requests - 1,
                response.failed.eq(1),
                request_counter_reset.eq(1),
                request_pending_clr.eq(1)
            ),
            response.mac_address.eq(cached_mac_address)
        ]
        fsm.act("PRESENT_RESPONSE",
            response.valid.eq(1),
            If(response.ready,
                NextState("IDLE")
            )
        )

# ARP ----------------------------------------------------------------------------------------------

class LiteEthARP(LiteXModule):
    def __init__(self, mac, mac_address, ip_address, clk_freq, dw=8):
        self.tx    = tx    = LiteEthARPTX(mac_address, ip_address, dw)
        self.rx    = rx    = LiteEthARPRX(mac_address, ip_address, dw)
        self.table = table = LiteEthARPTable(clk_freq)
        self.comb += [
            rx.source.connect(table.sink),
            table.source.connect(tx.sink)
        ]
        mac_port = mac.crossbar.get_port(ethernet_type_arp, dw=dw)
        self.comb += [
            tx.source.connect(mac_port.sink),
            mac_port.source.connect(rx.sink)
        ]
