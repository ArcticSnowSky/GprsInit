#!/usr/bin/env python3
#
# Script to prepare GPRS module with PIN and APN if required.
#
# Thomas Mailänder - 2018
#
import sys
import logging as log
import re

import configargparse
from serial import Serial  # pyserial

from lxml import etree
from difflib import SequenceMatcher

CFG_PATHS = ['/etc/gprsInit/*.conf', '~/.gprsInit']
APN_LIST_PATH = '/etc/apns.xml'
MODEM_EOL = "\r\n"
TIMEOUT = 10
MAX_RETRIES = 3


class GsmModem:

	class SimException(Exception):
		def __init__(self, message = None, errors = None):
			super().__init__(message)
			self.errors = errors

	class PinException(Exception):
		def __init__(self, message = None, errors = None):
			super().__init__(message)
			self.errors = errors

	class TransmissionException(Exception):
		def __init__(self, message = None, errors = None):
			super().__init__(message)
			self.errors = errors
	
	def __init__(self, cfg):
		self._serial = Serial(cfg.serPort, cfg.serBaud)
		self._serial.timeout = cfg.timeout
		log.debug("Default timeout: " + str(self._serial.timeout))
		self._cfg = cfg

	def __enter__(self):
		return self

	def __exit__(self, type, value, tb):
		self._serial.close()


	def write(self, text, timeout = None, waitForResponse = "OK", keepOriginal = False, repeatOnTransmissionError=True):
		if timeout:
			log.debug("GsmModem::write() Set Timeout from {0} to {1}".format(self._serial.timeout, timeout))
			origTimeout = self._serial.timeout
			self._serial.timeout = timeout
		
		log.debug("GsmModem::write() Send on serial: " + text)
		self._serial.read_all()
		self._serial.write((text + MODEM_EOL).encode())
		
		lines = []
		while waitForResponse != None:
			recv = self._serial.readline()
			if not recv:
				log.error("GsmModem::write() readline timeout")
				raise TimeoutError()
			
			try:
				resp = recv.decode().rstrip()
			except Exception as ex:
				raise GsmModem.TransmissionException(ex)
			
			lines.append(resp)
			if resp == waitForResponse:
				log.debug("GsmModem::write() readline " + resp)
				break
			elif resp == "ERROR":
				log.error("GsmModem::write() readline " + resp)
				if repeatOnTransmissionError:
					return self.write(text, timeout, waitForResponse, keepOriginal, False)
				break
			else:
				log.debug("GsmModem::write() readline " + resp)
		
		if timeout:
			self._serial.timeout = origTimeout

		if waitForResponse != None and len(lines) > 0 and lines[0] != text:
			# probably error while sending
			if repeatOnTransmissionError:
				return self.write(text, timeout, waitForResponse, keepOriginal, False)
			else:
				raise GsmModem.TransmissionException()
		
		# Remove mirrored text
		if waitForResponse != None and not keepOriginal and lines[0] == text:
			del lines[0]
		
		return lines


	def readline(self, timeout = None):
		if timeout:
			origTimeout = self._serial.timeout
			self._serial.timeout = timeout

		recv = self._serial.readline()

		if timeout:
			self._serial.timeout = origTimeout

		if not recv:
			log.error("GsmModem::readline() timeout")
			raise TimeoutError

		resp = recv.decode().rstrip()
		log.debug("GsmModem::readline() Read on serial: " + resp)
		return resp

	def readlines(self, timeout = None):
		if timeout:
			origTimeout = self._serial.timeout
			self._serial.timeout = timeout

		recv = self._serial.readlines()
		
		if not recv:
			log.error("GsmModem::readlines() timeout")
			raise TimeoutError

		if timeout:
			self._serial.timeout = origTimeout

		resp = recv.decode()
		log.info("GsmModem::readlines() Read on serial: " + resp)
		return resp


	def pinHandling(self, pin = None):
		resp = self.write("AT+CPIN?")
		if self.messageResult(resp) == False:
			raise GsmModem.SimException("No contact to SimCard")
		
		if any("SIM PIN" in s for s in resp):
			log.info("Pin required")
			if pin:
				self.write("AT+CPIN=\""+pin+"\"")
				log.info("Pin sent")
				resp = self.write("AT+CPIN?")
			else:
				raise GsmModem.PinException("Pin required")
		
		if any("PUK" in s for s in resp):
			raise GsmModem.PinException("Puk required! You have to unlock manually!")
		
		if not any("READY" in s for s in resp):
			raise GsmModem.PinException("Wrong pin")
		log.info("Pin ok")

	def apnHandling(self, apn = None):
		if apn == None or len(apn) <= 0:
			log.info("Searching APN...")
			resp = self.write("AT+COPS?")
			opName = ""
			if self.messageResult(resp):
				line = [s for s in resp if "+COPS:" in s][0]
				opName = line.split('"')[1]
				log.info("Received COPS {} ({})".format(opName, line))
				
			resp = self.write("AT+CIMI")
			if self.messageResult(resp):
				for s in resp:
					if len(s) >= 5:
						log.debug("Received IMSI {}".format(s))
						apn = self.searchApn(s[:3], s[3:5], opName)
						log.info("chosen apn: {}".format(apn))

		resp = self.write("AT+CGDCONT?")
		if self.messageResult(resp) == False:
			raise GsmModem.SimException("No contact to SimCard")
		
		cid = 0
		cid_count = 0
		if any("+CGDCONT:" in s for s in resp):
			for s in resp:
				if apn in s:
					cid = int(re.findall(r'^\D*(\d+)', s)[0])
					cid_count+=1
					log.info("apnHandling: {0} {1} matched".format(cid_count, s))
				elif "+CGDCONT:" in s:
					cid_count+=1
					log.info("apnHandling: {0} {1}".format(cid_count, s))

		if cid > 0 and cid <= 5:
			return cid
		else:
			self.write("AT+CGDCONT={0},\"IP\",{1}".format(min(cid_count +1, 5), apn))
			return min(cid_count +1, 5)


	def messageResult(self, msg, required="OK"):
		if msg[-1] == required:
			return True
		elif msg[-1] == "ERROR":
			return False
		else:
			return None


	def prepare(self, pin = None, apn = None):
		self.write("AT")
		
		self.pinHandling(pin)
		cid = self.apnHandling(apn)
		log.info("GsmModem::prepare(pin = {0}, apn = {1}) = cid = {2}".format(pin, apn, cid))
		
		#self.write("AT+COPS?")
		#self.write("AT+CGDCONT?")

		return cid

	def connect(self, cid = 1):
		self.write("ATH")
		self.write("AT&K0")	# NoFlowControl otherwhise no "Connect" response
		if cid == None:
			cid = 1
		resp = self.write("ATD*99***{0}#".format(cid), waitForResponse="CONNECT", timeout=30)
		return self.messageResult(resp, "CONNECT")

	def searchApn(self, mcc="222", mnc="01", opName="", default="internet"):
		log.debug("GsmModem::searchApn({}, {}, {}, {})".format(mcc, mnc, opName, default))

		xmldoc = etree.parse(APN_LIST_PATH)
		apnlist = xmldoc.xpath('//apn[@mcc="{0}"][@mnc="{1}"][@type="default,supl" or @type="default" or @type="dun"]'.format(mcc, mnc))
		
		apn_cnt = len(apnlist)
		bestApn = None
		
		if apn_cnt > 0:
			bestApn = apnlist[0]
		else:
			return default
		
		if apn_cnt > 1:
			getOpName = etree.XPath('@carrier')
			matchRatio = 0
			for apn in apnlist:
				itemOpName = getOpName(apn)[0]
				_matchRatio = SequenceMatcher(None, opName, itemOpName).ratio()
				log.debug("GsmModem::searchApn(): listitem: {}, ratio {}".format(itemOpName, _matchRatio))
				if _matchRatio > matchRatio:
					matchRatio = _matchRatio
					bestApn = apn
			
		apn = bestApn.xpath('@apn')[0]
		log.info("GsmModem::searchApn(): Best APN: {}".format(apn))
		return apn



def main(argv=None):

	VERSION = 0.3

	argp = configargparse.ArgParser(default_config_files=CFG_PATHS)
	argp.add_argument('-s', '--serial', dest='serPort', default='/dev/serial0', type=str, help="Serial interface")
	argp.add_argument('-b', '--baudrate', dest='serBaud', default='115200', type=str, help="Baudrate of modem")
	argp.add_argument('-p', '--pin', dest='pin', default='', type=str, help="Pin for simcard (Be aware wrong pin could result in PUK request!")
	argp.add_argument('-a', '--apn', dest='apn', default=None, type=str, help="APN for simcard (Empty APN searches for Dictionary APN, else remains empty)")
	argp.add_argument('-e', '--extra', dest='extra', default=None, type=str, help="Additional lines of AT Commands (After PIN/APN, before Connect)")
	argp.add_argument('-e1', '--extra1', dest='extra1', default=None, type=str, help="Additional lines after extra")
	argp.add_argument('-e2', '--extra2', dest='extra2', default=None, type=str, help="Additional lines after extra")
	argp.add_argument('-e3', '--extra3', dest='extra3', default=None, type=str, help="Additional lines after extra")
	argp.add_argument('-e4', '--extra4', dest='extra4', default=None, type=str, help="Additional lines after extra")
	argp.add_argument('-e5', '--extra5', dest='extra5', default=None, type=str, help="Additional lines after extra")
	argp.add_argument('-t', '--timeout', dest='timeout', default=TIMEOUT, type=float, help="Timeout per AT commands")
	argp.add_argument('-c', '--check', action="store_true", dest='check', help="Prepares PIN and APN but does not connect")
	argp.add_argument('--version', help="Show version", action='version', version='%(prog)s v{}'.format(VERSION))
	argp.add_argument('-v', '--verbose', action='count', dest='verbose', default=0, help='Be verbose')

	# Parse command line    
	cfg = argp.parse_args()
	verbose = 60 - min(5, cfg.verbose)*10
	log.basicConfig(format="%(levelname)s: %(message)s", level=verbose)
	log.debug("verbose")
	log.info("verbose")
	log.warn("verbose")
	log.error("verbose")
	log.critical("verbose")
	
	apn = cfg.apn.strip()[1:-1]
	pin = cfg.pin.strip()[1:-1]
	
	if cfg.check:
		log.info('Only checking PIN and APN')
	log.debug('Apn: {0}, Pin: {1}'.format(apn, pin))
	log.info('Opening serialport ' + cfg.serPort + ' with ' + str(cfg.serBaud))
	tries = 0
	errCode = 0
	success = False
	try:
		with GsmModem(cfg) as modem:
			while tries < MAX_RETRIES:
				tries+=1
				try:
					cid = modem.prepare(pin, apn)
					
					if cfg.extra:
						modem.write(cfg.extra)
					if cfg.extra1:
						modem.write(cfg.extra1)
					if cfg.extra2:
						modem.write(cfg.extra2)
					if cfg.extra3:
						modem.write(cfg.extra3)
					if cfg.extra4:
						modem.write(cfg.extra4)
					if cfg.extra5:
						modem.write(cfg.extra5)
					
					if cfg.check:
						success = True # If no exception has been thrown, all is ok
					else:
					    success = modem.connect(cid)
					break
				except TimeoutError as tex:
					errCode = -2
					log.error("GprsInit: Timeout, retries left: " + str(MAX_RETRIES-tries))

	except Exception as ex:
		errCode = -1
		log.error("GprsInit: {}".format(ex))

	log.info('GprsInit finished, success = {0}, errCode = {1}'.format(success, errCode))
	if success:
		return 0
	else:
		return errCode

if __name__ == "__main__":
	sys.exit(main())
