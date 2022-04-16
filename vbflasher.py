#!/usr/bin/env python3

"""
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
from time import sleep, time
from math import ceil
from io import BytesIO

import can
from subprocess import Popen, PIPE

from ford.vbf import Vbf
from ford.uds import keygen, fixedbytes, Ecu


def tccheck(can_interface):	
	cmd = "tc qdisc show | grep {} | cut -f2 -d' '".format(can_interface)

	with Popen(cmd, shell=True, stdout=PIPE, preexec_fn=os.setsid) as process:
	    output = process.communicate()[0]

	if output:
		if 'fifo' in output.decode("utf-8"):
			return True

	return False


class Vbflasher:
	def __init__(self, can_interface="can0", self.ecuid="none"):
		self.ecuid = None
	

			if self.ecuid:
				if self.ecuid != self.data.ecuid:
					die("[!] Loaded VBF file for a different ECU than before. Aborting.")
			else:
				self.ecuid = self.data.ecuid

		if self.ecuid:
			self.ecu = Ecu(can_interface=can_interface, ecuid=self.ecuid)
			if not tccheck(can_interface):
				die("[!] Please set {} qdisc to pfifo_fast. Now it's too risky to continue...".format(can_interface))
		else:
			die("[!] No valid VBF loaded...")


	def tester(self):
		debug("[+] Sending TesterPresent to 0x{:x}... ".format(self.ecuid), end="")
		if self.ecu.UDSTesterPresent():
			debug("OK")
		else:
			die("\n[-] 0x{:x} did not send positive reposnse to our tester message... Aborting".format(self.ecuid))

	def start(self):
		debug("\n[+] Starting Diagnostic Session 0x02... ", end="")
		if self.ecu.UDSDiagnosticSessionControl(0x02): # 0x02
			debug("OK")
		else:
			die("\n[-] Unable to start diagnostic session. Aborting.")
		sleep(1)

		debug("[ ] Unlocking the ECU...")
		res, msg = self.ecu.unlock(0x01) # 0x01
		if res:
			debug(msg)
		else:
			die(msg)

	def testerloop(self):
		while  True:
			self.ecu.UDSTesterPresent();
			sleep(1)


def usage(str):
	print('usage: {} interface ecuid'.format(str))


def debug(str, end="\n"):
	print(str, end=end)
	sys.stdout.flush()


def die(str):
	print(str)
	sys.exit(-1)


if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage(sys.argv[0])
		sys.exit(-1)

	iface = sys.argv[1]
	ecuid = sys.argv[2]

	try:
		flasher = Vbflasher(can_interface=iface, ecuid=ecuid)
	except OSError as e:
		enum = e.args[0]
		if enum == 19:
			die('[!] Unable to open device {}'.format(iface))
		if enum == 99:
			die('[!] Unable to assign ecu address = {}'.format(ecuid))
		die(e)

	debug("\n[+] Successfully opened {}".format(iface))

	flasher.start()
	
