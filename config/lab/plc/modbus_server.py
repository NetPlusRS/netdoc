"""Prosty serwer Modbus TCP — symuluje sterownik PLC."""
import os
import time
import logging
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

DEVICE_NAME = os.getenv("PLC_NAME", "PLC-1")
HOLDING_REGS = list(range(100))   # 100 rejestrów holding

store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [0] * 100),
    co=ModbusSequentialDataBlock(0, [0] * 100),
    hr=ModbusSequentialDataBlock(0, HOLDING_REGS),
    ir=ModbusSequentialDataBlock(0, HOLDING_REGS),
)
context = ModbusServerContext(slaves=store, single=True)

logger.info("Uruchamianie serwera Modbus TCP na porcie 502 (%s)", DEVICE_NAME)
StartTcpServer(context=context, address=("0.0.0.0", 502))
