import pefile 
import argparse
import os
import re
import logging
import sys
import binascii

log = logging.getLogger()


desc = "PE Dump is a swiss knife analysis tool for PE files"


def hextobytes(enc_str):
	result = []
	s_len = len(enc_str)
	if s_len > 2:
		j = s_len / 2
		for x in xrange(j):
			result.append(int(enc_str[(x*2):(2+x*2)],base=16))

	return str(bytearray(result))

def main():

	log.setLevel(logging.DEBUG)
	console = logging.StreamHandler()
	log.addHandler(console)

	parser = argparse.ArgumentParser(prog = 'PE Dump', description='{0}'.format(desc), epilog = 'Copyright amz 2015')
	parser.add_argument('pefile', help='The PE file to disect.')
	# parser.add_argument('-g', '--get', choices=['report','domain','file', 'profile', 'url', 'ip'])
	# parser.add_argument('-s', '--search', choices=['email','files', 'group', 'actors'], help='Searches MATI reports by type of value')
	# parser.add_argument('-f', '--file',help='Json File to include result')
	options = parser.parse_args()

	fpath = os.path.abspath(options.pefile)
	if not os.path.exists(fpath):
		log.error("File not found!")

	pe32 = pefile.PE(fpath)

	if not hex(pe32.DOS_HEADER.e_magic) == '0x5a4d':
		log.error("E_MAGIC not MZ!")

	if pe32.get_warnings():
		print pe32.get_warnings()

	generated = pe32.generate_checksum()
	if pe32.OPTIONAL_HEADER.CheckSum != generated:
		log.warning('CheckSum mismatch. CheckSum value in header = %s',(hex(pe32.OPTIONAL_HEADER.CheckSum)))

	ep = pe32.OPTIONAL_HEADER.AddressOfEntryPoint
	log.debug('EP= %s',hex(ep))
	ep_section = pe32.get_section_by_rva(ep)

	if ep_section.Name != pe32.sections[0].Name:
		log.warning('Entry point not in first section')

	if pe32.is_dll():
		log.info("File Type: DLL")
	elif pe32.is_driver():
		log.info("File Type: Driver")
	elif pe32.is_exe():
		log.info("File Type: EXE")

	temp  = []
	for section in pe32.sections:
		log.info('Section: %s, Size: %s, Entropy %f',section.Name,hex(section.SizeOfRawData),section.get_entropy())
		sec_dict = {'name': section.Name, 'start': section.PointerToRawData, 'end': section.PointerToRawData+section.SizeOfRawData}

		if section.SizeOfRawData == 0:
			log.warning('Section %s has Zero size !',section.Name)

		if section.IMAGE_SCN_MEM_EXECUTE:
			if section.SizeOfRawData <= int('200',16):
				log.warning('Executable section %s with size less than 0x200',section.Name)

			if '.text' not in section.Name:
				log.warning('Non .text executable section %s ',section.Name)

		if section.Name.startswith('.text'):
			#https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx

			if not section.IMAGE_SCN_CNT_CODE:
				log.warning('.text section not marked as code')

			if section.IMAGE_SCN_MEM_WRITE:
				log.warning('Writable .text section')

			if not section.IMAGE_SCN_MEM_READ:
				log.warning('.text section not readable')

			if not section.IMAGE_SCN_MEM_EXECUTE:
				log.warning('.text section not executable')


		elif section.Name.startswith('.data'):

			if section.IMAGE_SCN_MEM_EXECUTE:
				log.warning('.data section executable')

			if not section.IMAGE_SCN_MEM_READ:
				log.warning('.data section not readable')


		temp.append(sec_dict)
		if len(temp) > 1:
			current_section  = temp[-1]
			previous_section = temp[-2]
			if hex(previous_section['end']) < hex(current_section['start']):
				log.warning('Found slack space !')
				slack_size = current_section['start'] - previous_section['end']
				log.warning('Start offset: %s, Size: %s',hex(previous_section['end']),hex(slack_size))
				offset_rva = pe32.get_rva_from_offset(previous_section['end'])
				data = pe32.get_data(offset_rva,slack_size)
				log.warning('Data: %s ...',(binascii.hexlify(data[1:64])))

	log.info("=== Version Info ===")
	# for info in pe32.FileInfo:
	# 	log.debug('Struct %s',info)




	sys.exit(0)

if __name__ == '__main__':
	main()