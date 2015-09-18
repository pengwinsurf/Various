import pefile 
import argparse
import os
import re
import logging
import sys
import binascii
import datetime 
import peutils

log = logging.getLogger()


desc = "PE Dump is a swiss knife analysis tool for PE files"


class Trait(object):

	def __init__(self,name):
		self.name = name
		self.value = None 

class File(object):

	def __init__(self,path):
		self.pe = pefile.PE(path)
		self.traits = {}

	def __basic_checks(self):
		generated = self.pe.generate_checksum()
		if self.pe.OPTIONAL_HEADER.CheckSum != generated:
			log.warning('CheckSum mismatch. CheckSum value in header = %s',(hex(self.pe.OPTIONAL_HEADER.CheckSum)))
			self.traits['BAD_CHECKSUM'] = True

		ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		ep_section = self.pe.get_section_by_rva(ep)

		if ep_section.Name != self.pe.sections[0].Name:
			log.warning('Entry point not in first section')
			self.traits['EP_NOT_1st_SECTION'] = True

	def basic_info(self):
		log.info("Compile date: %s",datetime.date.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp))
		self.traits['COMPILE_DATE'] = datetime.date.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)
		if self.pe.is_dll():
			log.info("File Type: DLL\n")
			self.traits['DLL'] = True
		elif self.pe.is_driver():
			log.info("File Type: Driver\n")
			self.traits['DRIVER'] = True
		elif self.pe.is_exe():
			log.info("File Type: EXE\n")
			self.traits['EXE'] = True

		self.__basic_checks()

	def read_sections(self):
		temp  = []
		for section in self.pe.sections:
			log.info('Section: %s, Size: %s, Entropy %f',section.Name,hex(section.SizeOfRawData),section.get_entropy())
			sec_dict = {'name': section.Name, 'start': section.PointerToRawData, 'end': section.PointerToRawData+section.SizeOfRawData}

			if section.SizeOfRawData == 0:
				log.warning('Section %s has Zero size !',section.Name)
				self.traits['ZERO_SIZE_SECTION'] = section.Name

			if section.IMAGE_SCN_MEM_EXECUTE:
				if section.SizeOfRawData <= int('200',16):
					log.warning('Executable section %s with size less than 0x200',section.Name)
					self.traits['X_SECTION_SMALLER_THAN_200'] = section.Name

				if '.text' not in section.Name:
					log.warning('Non .text executable section %s ',section.Name)
					if 'OTHER_X_SECTION' in self.traits:
						self.traits['MULTIPLE_X_SECTIONS'] = True
					else:
						self.traits['OTHER_X_SECTION'] = section.Name

			if section.Name.startswith('.text'):
				#https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx

				if not section.IMAGE_SCN_CNT_CODE:
					log.warning('.text section not marked as code')
					self.traits['TEXT_SECTION_NOT_MARKED_CODE'] = True

				if section.IMAGE_SCN_MEM_WRITE:
					log.warning('Writable .text section')
					self.traits['TEXT_SECTION_WRITABLE'] = True

				if not section.IMAGE_SCN_MEM_READ:
					log.warning('.text section not readable')
					self.traits['TEXT_SECTION_NOT_READABLE'] = True


				if not section.IMAGE_SCN_MEM_EXECUTE:
					log.warning('.text section not executable')
					self.traits['TEXT_SECTION_NOT_X'] = True


			elif section.Name.startswith('.data'):

				if section.IMAGE_SCN_MEM_EXECUTE:
					log.warning('.data section executable')
					self.traits['DATA_SECTION_X'] = True

				if not section.IMAGE_SCN_MEM_READ:
					log.warning('.data section not readable')
					self.traits['DATA_SECTION_NOT_READABLE'] = True


			temp.append(sec_dict)
			if len(temp) > 1:
				current_section  = temp[-1]
				previous_section = temp[-2]
				if hex(previous_section['end']) < hex(current_section['start']):
					log.warning('Found slack space !')
					slack_size = current_section['start'] - previous_section['end']
					log.warning('Start offset: %s, Size: %s',hex(previous_section['end']),hex(slack_size))
					self.traits['SLACK_SPACE'] = slack_size
					offset_rva = self.pe.get_rva_from_offset(previous_section['end'])
					data = self.pe.get_data(offset_rva,slack_size)
					log.warning('Data: %s ...',(binascii.hexlify(data[1:64])))
					self.traits['SLACK_DATA'] = data

	def analyze_data(self,rva_offset,size):

		data = self.pe.get_data(rva_offset,size)
		hex_data = binascii.hexlify(data)
		section = self.pe.get_section_by_rva(rva_offset)
		data_entropy = section.entropy_H(data)
		log.info("Data Entropy: %f",data_entropy)

		if hex_data[:2] == '4D5A':
			log.warning("Found MZ at start of RVA: %s", hex(rva_offset))
			self.traits['MZ_IN_DATA_BLOCK'] = rva_offset

		if 'aPLib'.encode('hex') in hex_data: # aPLib
			log.warning("Potentially aPLib compressed data found at RVA: %s", rva_offset)
			self.traits['APLIB_COMPRESSED_DATA'] = rva_offset

		if 'This program cannot be run in DOS mode'.encode('hex') in hex_data:
			log.warning("Potential DOS header found in data at RVA: %s", rva_offset)
			self.traits['DOS_HEADER_IN_DATA'] = rva_offset

		return data

	def __walk_resources(self,rsrc_dir,depth):

		for entry in rsrc_dir.entries:
			try:
				rsrc_data = entry.data
				log.info("Lang: %s", pefile.LANG[rsrc_data.lang])
				if pefile.LANG[rsrc_data.lang] is not 'LANG_ENGLISH':
					self.traits['NON_ENGLISH_RSRCS_LANG'] = pefile.LANG[rsrc_data.lang]
				log.info("Size: %s", hex(rsrc_data.struct.Size))
				self.analyze_data(rsrc_data.struct.OffsetToData,rsrc_data.struct.Size)
				log.info("--------------\n")
				return

			except AttributeError:
				if depth == 0:
					if entry.name:
						log.info("Resource Name: %s", entry.name)
					else:
						log.info("Resource ID %s  - Type: %s",hex(entry.id),pefile.RESOURCE_TYPE[entry.id])
						if pefile.RESOURCE_TYPE[entry.id] == 'RCDATA':
							self.traits['RCDATA_IN_RESOURCES'] = True
				else:
					if entry.name:
						log.info("Child Resource Name: %s\n", entry.name)
					else:
						log.info("Child Resource ID:  %s", entry.id)

				depth += 1
				self.__walk_resources(entry.directory,depth)
				depth = depth - 1

	def read_version_info(self):
		log.info("\n")
		log.info("=== Version Info ===")
		try:
			for info in self.pe.FileInfo:
				self.traits['VERSION_INFO'] = True
				if info.Key == 'StringFileInfo':
					for ver in info.StringTable:
						for label,data in ver.entries.iteritems():
							if 'Microsoft' in data:
								MicrosoftVersionInfo = True
								self.traits['MS_VERSION_INFO'] = True

							if 'Adobe' in data:
								AdobeVersionInfo = True
								self.traits['ADOBE_VERSION_INFO'] = True

							log.info("%s : %s",label,data)
			# elif info.Key == 'VarFileInfo':
			# 	for ver in info.Var:
			# 		for key,val in ver.entry.iteritems():
			# 			log.info("%s : %s", key, val)
		except AttributeError:
			log.info("No Version Information found")
			self.traits['NO_VERSION_INFO'] = True

	def read_resources(self):
		log.info("=== Resources ===")
		rsrc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
		rsrc_root = self.pe.parse_resources_directory(rva=rsrc_dir.VirtualAddress)
		if rsrc_root:
			log.info("Number of rsrcs: %s \n",rsrc_root.struct.NumberOfNamedEntries + rsrc_root.struct.NumberOfIdEntries)
			self.traits['NUMBER_OF_RSRCS'] = rsrc_root.struct.NumberOfNamedEntries + rsrc_root.struct.NumberOfIdEntries
			depth = 0
			self.__walk_resources(rsrc_root,depth)
			log.info("****** Resources Strings *******")
			strings = self.pe.get_resources_strings()
			if not strings:
				log.info("No strings found")
			else:
				self.traits['STRINGS_IN_RSRCS'] = True
				for string in strings:
					log.info("%s", string)

		else:
			log.info("No resources found")

		log.info("==================\n")

	def read_debug_data(self):
		## Find PDB data
		try:

			for debug in self.pe.DIRECTORY_ENTRY_DEBUG:
				if pefile.DEBUG_TYPE[debug.struct.Type] == 'IMAGE_DEBUG_TYPE_CODEVIEW':
					data = self.pe.get_data(debug.struct.AddressOfRawData)
					hex_data = binascii.hexlify(data)
					if 'RSDS'.encode('hex') == hex_data[:8]:
								# struct CV_INFO_PDB70
								# {
							# 			DWORD  CvSignature;
							# 			GUID Signature;
							# 			DWORD Age;
							# 			BYTE PdbFileName[];
								# } ;

						temp_hex = binascii.hexlify(data[24:]).rstrip('0000')
						raw_pdb = binascii.unhexlify(temp_hex)
						log.info("PDB file: %s",raw_pdb.encode('utf-8'))
						self.traits['PDB_FOUND'] = raw_pdb.encode('utf-8')
						self.traits['CODE_VIEW_7.0'] = True
					elif 'NB10'.encode('hex') == hex_data[:8]:
							# 	struct CV_INFO_PDB20
							# {
						# 			CV_HEADER CvHeader;
						# 			DWORD Signature;
						# 			DWORD Age;
						# 			BYTE PdbFileName[];
							# };
						temp_hex = binascii.hexlify(data[16:]).rstrip('0000')
						raw_pdb = binascii.unhexlify(temp_hex)
						log.info("PDB file: %s",raw_pdb.encode('utf-8'))
						self.traits['PDB_FOUND'] = raw_pdb.encode('utf-8')
						self.traits['CODE_VIEW_2.0'] = True
		except AttributeError:

			log.info("No Debug Information found")
			self.traits["NO_DEBUG_INFO"] = True

	def check_peid_sigs(self,sig_fpath):
		signatures = peutils.SignatureDatabase(sig_fpath)

		matches = signatures.match(self.pe, ep_only=True)

		if not matches:
			log.info("No PEID matches found")
			return

		for match in matches:
			log.info("PEID Match: %s", match)
			self.traits['PEID_{0}'.format(match)] = True



def main():

	log.setLevel(logging.DEBUG)
	console = logging.StreamHandler()
	log.addHandler(console)

	parser = argparse.ArgumentParser(prog = 'PE Dump', description='{0}'.format(desc), epilog = 'Copyright amz 2015')
	parser.add_argument('pefile', help='The PE file to disect.')
	parser.add_argument('-s', '--signatures', help='Path to PEID signatures file')
	# parser.add_argument('-s', '--search', choices=['email','files', 'group', 'actors'], help='Searches MATI reports by type of value')
	# parser.add_argument('-f', '--file',help='Json File to include result')
	options = parser.parse_args()

	fpath = os.path.abspath(options.pefile)
	if not os.path.exists(fpath):
		log.error("PE File not found!")

	spath = os.path.abspath(options.signatures)
	if not os.path.exists(spath):
		log.error("Signatures File not found!")

	exe = File(fpath)

	exe.basic_info()

	exe.read_sections()

	exe.read_resources()

	exe.read_version_info()

	exe.read_debug_data()

	exe.check_peid_sigs(spath)






	sys.exit(0)

if __name__ == '__main__':
	main()