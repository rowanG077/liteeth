from liteeth.common import *
from liteeth.frontend.tty import LiteEthTTY

from targets.base import BaseSoC


class TTYSoC(BaseSoC):
    default_platform = "kc705"
    def __init__(self, platform):
        BaseSoC.__init__(self, platform,
            mac_address=0x10e2d5000000,
            ip_address="192.168.1.50")
        self.submodules.tty = LiteEthTTY(self.core.udp, convert_ip("192.168.1.100"), 10000)
        self.comb += self.tty.source.connect(self.tty.sink)


class TTYSoCDevel(TTYSoC):
    csr_map = {
        "logic_analyzer":            20
    }
    csr_map.update(TTYSoC.csr_map)
    def __init__(self, platform):
        from litescope.frontend.logic_analyzer import LiteScopeLogicAnalyzer
        from litescope.core.port import LiteScopeTerm
        TTYSoC.__init__(self, platform)
        debug = (
            self.tty.sink.valid,
            self.tty.sink.ready,
            self.tty.sink.data,

            self.tty.source.valid,
            self.tty.source.ready,
            self.tty.source.data
        )
        self.submodules.logic_analyzer = LiteScopeLogicAnalyzer(debug, 4096)
        self.logic_analyzer.trigger.add_port(LiteScopeTerm(self.logic_analyzer.dw))

    def do_exit(self, vns):
        self.logic_analyzer.export(vns, "test/logic_analyzer.csv")

default_subtarget = TTYSoC
