#!/bin/sh
# Podmien zmienne srodowiskowe w snmpd.conf
sed -i "s|\${PLC_SNMP_DESCR:-[^}]*}|${PLC_SNMP_DESCR:-Siemens SIMATIC S7-1200 PLC}|g" /etc/snmp/snmpd.conf
sed -i "s|\${PLC_SNMP_NAME:-[^}]*}|${PLC_SNMP_NAME:-PLC-1}|g" /etc/snmp/snmpd.conf
sed -i "s|\${PLC_SNMP_LOC:-[^}]*}|${PLC_SNMP_LOC:-Hala produkcyjna A}|g" /etc/snmp/snmpd.conf

# Uruchom snmpd w tle
snmpd -Lo -c /etc/snmp/snmpd.conf &

# Uruchom Modbus TCP
exec python3 /app/modbus_server.py
