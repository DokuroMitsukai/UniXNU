"""ADT interrupt-parent conversion tests."""
import struct
import unittest

from .devicetree import FdtNode, hardware_properties
from .util import Error


def cells(*values):
    return struct.pack('>' + 'I' * len(values), *values)


class InterruptParentTests(unittest.TestCase):
    def setUp(self):
        self.root = FdtNode('device-tree', properties={'interrupt-parent': cells(1)})
        self.intc = FdtNode('intc', parent=self.root, properties={
            'phandle': cells(1),
            '#interrupt-cells': cells(3),
            'interrupt-controller': b'',
            'interrupts': cells(1, 9, 4),
        })
        self.peripheral = FdtNode('dev', parent=self.root, properties={
            'interrupts': cells(0, 5, 4),
        })
        self.handles = {1: self.intc}

    def test_phandle_is_emitted_as_aapl_phandle(self):
        properties = dict(hardware_properties(self.intc, self.handles))
        self.assertEqual(properties['AAPL,phandle'], struct.pack('<I', 1))
        self.assertNotIn('phandle', properties)

    def test_interrupt_parent_resolves_for_controller_and_peripheral(self):
        controller = dict(hardware_properties(self.intc, self.handles))
        peripheral = dict(hardware_properties(self.peripheral, self.handles))
        self.assertEqual(controller['interrupt-parent'], struct.pack('<I', 1))
        self.assertEqual(peripheral['interrupt-parent'], struct.pack('<I', 1))
        self.assertEqual(peripheral['interrupts'], struct.pack('<3I', 0, 5, 4))

    def test_unresolved_interrupt_parent_is_rejected(self):
        self.root.properties['interrupt-parent'] = cells(2)
        with self.assertRaisesRegex(Error, 'interrupt provider or specifier is invalid'):
            hardware_properties(self.peripheral, self.handles)


if __name__ == '__main__':
    unittest.main()
