import pefile 
import argparse
import os
import re
import logging
import sys
import binascii
import datetime 

log = logging.getLogger()


desc = "PE Dump is a swiss knife analysis tool for PE files"

def analyze(rva_offset,size,pe32):

	data = pe32.get_data(rva_offset,size)
	hex_data = binascii.hexlify(data)
	section = pe32.get_section_by_rva(rva_offset)
	data_entropy = section.entropy_H(data)
	log.info("Data Entropy: %f",data_entropy)

	if hex_data[:2] == '4D5A':
		log.warning("Found MZ at start of RVA: %s", hex(rva_offset))

	if 'aPLib'.encode('hex') in hex_data: # aPLib
		log.warning("Potentially aPLib compressed data found at RVA: %s", rva_offset)

	if 'This program cannot be run in DOS mode'.encode('hex') in hex_data:
		log.warning("Potential DOS header found in data at RVA: %s", rva_offset)

	return data


def read_resources(rsrc_dir,pe32,depth):
		for entry in rsrc_dir.entries:
			try:
				rsrc_data = entry.data
				log.info("Lang: %s", pefile.LANG[rsrc_data.lang])
				log.info("Size: %s", hex(rsrc_data.struct.Size))
				analyze(rsrc_data.struct.OffsetToData,rsrc_data.struct.Size,pe32)
				log.info("--------------\n")
				return

			except AttributeError:
				if depth == 0:
					if entry.name:
						log.info("Resource Name: %s", entry.name)
					else:
						log.info("Resource ID %s  - Type: %s",hex(entry.id),pefile.RESOURCE_TYPE[entry.id])
				else:
					if entry.name:
						log.info("Child Resource Name: %s\n", entry.name)
					else:
						log.info("Child Resource ID:  %s", entry.id)

				depth += 1
				read_resources(entry.directory,pe32,depth)
				depth = depth - 1

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
	ep_section = pe32.get_section_by_rva(ep)

	if ep_section.Name != pe32.sections[0].Name:
		log.warning('Entry point not in first section')

	log.info("Compile date: %s",datetime.date.fromtimestamp(pe32.FILE_HEADER.TimeDateStamp))
	if pe32.is_dll():
		log.info("File Type: DLL\n")
	elif pe32.is_driver():
		log.info("File Type: Driver\n")
	elif pe32.is_exe():
		log.info("File Type: EXE\n")

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

	log.info("\n")
	log.info("=== Version Info ===")

	try:
		for info in pe32.FileInfo:
			if info.Key == 'StringFileInfo':
				for ver in info.StringTable:
					for label,data in ver.entries.iteritems():

						if 'Microsoft' in data:
							MicrosoftVersionInfo = True

						if 'Adobe' in data:
							AdobeVersionInfo = True

						log.info("%s : %s",label,data)
		# elif info.Key == 'VarFileInfo':
		# 	for ver in info.Var:
		# 		for key,val in ver.entry.iteritems():
		# 			log.info("%s : %s", key, val)
	except AttributeError:
		log.info("No Version Information found")



	log.info("==================\n")

	### Resources

	log.info("=== Resources ===")

	rsrc_dir = pe32.OPTIONAL_HEADER.DATA_DIRECTORY[2]
	rsrc_root = pe32.parse_resources_directory(rva=rsrc_dir.VirtualAddress)
	if rsrc_root:
		log.info("Number of rsrcs: %s \n",rsrc_root.struct.NumberOfNamedEntries + rsrc_root.struct.NumberOfIdEntries)
		depth = 0
		read_resources(rsrc_root,pe32,depth)
		log.info("****** Resources Strings *******")
		strings = pe32.get_resources_strings()
		if not strings:
			log.info("No strings found")
		else:
			for string in strings:
				log.info("%s", string)

	else:
		log.info("No resources found")

	log.info("==================\n")


	## Find PDB data
	for debug in pe32.DIRECTORY_ENTRY_DEBUG:
		if pefile.DEBUG_TYPE[debug.struct.Type] == 'IMAGE_DEBUG_TYPE_CODEVIEW':
			data = pe32.get_data(debug.struct.AddressOfRawData)
			hex_data = binascii.hexlify(data)
			if 'RSDS'.encode('hex') == hex_data[:8]:
				print hex_data[8:16]
			elif 'NB10'.encode('hex') == hex_data[:8]:
				pass



	sys.exit(0)

if __name__ == '__main__':
	main()