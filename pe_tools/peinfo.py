#!/usr/bin/python

""" Script to extract information from a PE file """

import argparse
import os
import binascii
import imp
import subprocess
import re
import datetime


import pefile


try:
    imp.find_module('M2Crypto')
    from M2Crypto import *
    OPENSSL = False
except ImportError:
    print "[!] M2Crypto not install, ensure openssl in path\n"
    OPENSSL = True

__author__ = "Pengwinsurf"
__copyright__ = "Copyright 2018"
__license__ = "MIT"
__version__ = "0.3"
__date__ = "07 Aug 2018"


class PeInfo():

    def __init__(self, filePath):
        self.filePath = os.path.abspath(filePath)
        self.pe = pefile.PE(os.path.abspath(filePath))
        self.expDirEnt = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        self.impDirEnt = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    
    def _read_pe_info(self):
        """
		Walks the PE sections loading standard info into the info dict and looking for anomalies
		"""
        print "Compile date: %s" % (datetime.date.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp))
        if self.pe.is_dll():
            print "File Type: DLL"
        elif self.pe.is_driver():
			print "File Type: Driver"
        elif self.pe.is_exe():
			print "File Type: EXE"
        else:
			print "Unidentified Type: %s" % hex(self.pe.FILE_HEADER.Characteristics)

        print "Machine: %s" % pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]

        print "Image base: 0x%08x" % self.pe.OPTIONAL_HEADER.ImageBase
        print "Image size: 0x%08x" % self.pe.OPTIONAL_HEADER.SizeOfImage

        print "EntryPoint RVA: 0x%08x" % self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print "EntryPoint in section: %s" % self.pe.get_section_by_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint).Name


        print "Section\tVirtualAddress\tPhysicalAddress\tVirtualSize\tPhysicalSize\tFlags\tEntropy"

        for section in self.pe.sections:
            characteristics = ''            
            if section.IMAGE_SCN_MEM_READ:
                characteristics += 'r'
            else:
                characteristics += '_'
            
            if section.IMAGE_SCN_MEM_WRITE:
                characteristics += 'w'
            else:
                characteristics += '_'
            
            if section.IMAGE_SCN_MEM_EXECUTE:
                characteristics += 'x'
            else:
                characteristics += '_'
            
            if section.IMAGE_SCN_CNT_CODE:
                characteristics += 'c'
            else:
                characteristics += '_'

            print "%s\t0x%08x\t0x%08x\t0x%08x\t0x%08x\t%s\t%d" % (section.Name, section.VirtualAddress, section.PointerToRawData,\
                    section.Misc_VirtualSize, section.SizeOfRawData, characteristics, section.get_entropy())
        
        pe_size = self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData
        ondisk_size = os.stat(self.filePath).st_size
        print "\n"

        if pe_size < ondisk_size:
            appended_data_sz = ondisk_size - pe_size
            print "Appended data offset\tSize"
            print "0x%08x\t0x%08x" % (pe_size, appended_data_sz)
    
    def _print_table(self, table):
        """ Helper function to print tables.
        Columns are Ordinal , VA, ExportName
        """

        for item in table:
            print "%d\t0x%08x\t%s" % (item[0], item[1], item[2])
        print "--------"

    def _parse_directory_descriptor(self, structType, dirEntry):
        """ Will parse the directory entry given a VA and size returning an instance of the
            directory descriptor
        """

        return self.pe.__unpack_data__(structType, self.pe.get_data(dirEntry.VirtualAddress, pefile.Structure(structType).sizeof()), file_offset=self.pe.get_offset_from_rva(dirEntry.VirtualAddress))

    def _get_export_addresses(self):
        """ Will walk the Function Table Addresses and return a list
            of each VA.
        """
        offset = 0
        exportAddresses = []
        for x in xrange(self.exportDir.NumberOfFunctions):
            exportAddresses.append(self.pe.get_dword_at_rva(
                self.exportDir.AddressOfFunctions + offset))
            offset = offset + 4

        return exportAddresses

    def _get_export_names(self):
        """ Based on the number of names in the Export Directory descriptor,
         return all export names
        """
        offset = 0
        exportNames = []
        for x in xrange(self.exportDir.NumberOfNames):
            nameAddress = self.pe.get_dword_at_rva(
                self.exportDir.AddressOfNames + offset)
            exportNames.append(self.pe.get_data(nameAddress).split('\x00')[0])
            offset = offset + 4

        return exportNames

    def _print_verinfo(self):
        """ Print version information is the file has any """

        print "[+]VERSION INFORMATION\n"
        if hasattr(self.pe, 'FileInfo'):
            for fileInfo in self.pe.FileInfo:
                if fileInfo.Key == 'StringFileInfo':
                    for vInfo in fileInfo.StringTable:
                        for info in vInfo.entries.items():
                            print "%s:\t%s" % (info[0], info[1])
        else:
            print "[!]No Version Information"

    def _print_debug_data(self):
        """ Print out Debug data if present """
        print "[+]DEBUG INFO\n"
        if (hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG')):

            for debug in self.pe.DIRECTORY_ENTRY_DEBUG:
                try:
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
                            print "[+]PDB file: %s\n" % raw_pdb.split('\x00')[0].encode('utf-8')

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
                            print "[+]PDB file: %s\n" % raw_pdb.split('\x00')[0].encode('utf-8')

                except (AttributeError,KeyError):
                    pass
        else:
            print"[!]No Debug Information"


    def _get_signature_info(self):
        """ Check if a PE is signed and get information about the signature
        """

        print "[+]Certificate information\n"
        securityDir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]

        if (securityDir.VirtualAddress == 0 and securityDir.Size == 0):
            print "[!]No Authenticode found"
            return 

        sigSize = securityDir.Size + securityDir.VirtualAddress
        sig = self.pe.write()[securityDir.VirtualAddress+8: sigSize]

        with open('cert.der', 'wb+') as fh:
            fh.write(sig)
            print "[+]Signature DER file dumped to cert.der"

        if not OPENSSL:
            file_handle  = open("cert.der", 'r')
            input_bio = BIO.File(file_handle)
            p7 = SMIME.PKCS7(m2.pkcs7_read_bio_der(input_bio._ptr()))
            #p7 = SMIME.load_pkcs7('temp.sig')

            signers = p7.get0_signers(X509.X509_Stack())

            for cert in signers:
                print "Issuer: %s " % cert.get_issuer().as_text()
                print "Not After: %s " % cert.get_not_after()
                print "Subject: %s " % cert.get_subject().as_text()

            file_handle.close()
        else:
            args = ['openssl', 'pkcs7', '-inform', 'DER', '-print_certs', '-text', '-in', 'cert.der']
            proc = subprocess.Popen(args, stdout=subprocess.PIPE)
            out, err = proc.communicate()

            with open('certinfo.txt', 'wb') as fh:
                fh.write(out)
                print "[+]Decoded Signature dumped to certinfo.txt"
            

            pCertInfo = re.compile(r'Issuer:(?P<issuer>\s.+)\s+Validity\s+Not Before:(?P<startdate>\s.*)\s+Not After :(?P<enddate>\s.+)\s+Subject:(?P<subject>\s.+)')
            pCodeSign = re.search(r"X509v3 Extended Key Usage:.*[\n\s]+Code Signing", out)

            if pCodeSign:
                endPos = pCodeSign.span()[0] # This will be the end marker for us
                matches = pCertInfo.findall(out,endpos=endPos)
                print "Issuer: %s" % matches[-1][0]
                print "Valid From: %s" % matches[-1][1]
                print "Valid To: %s" % matches[-1][2]
                print "Subject: %s" % matches[-1][3]

    def _read_resources(self):
        print "[+] Resources information"
        rsrc_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        rsrc_root = self.pe.parse_resources_directory(rva=rsrc_dir.VirtualAddress)
        if rsrc_root:
            print "Number of rsrcs: %s" % (rsrc_root.struct.NumberOfNamedEntries + rsrc_root.struct.NumberOfIdEntries)
            depth = 0
            self._walk_resources(rsrc_root,depth)
			# log.info("****** Resources Strings *******")
			# strings = self.pe.get_resources_strings()
			# if not strings:
			# 	log.info("No strings found")
			# else:
			# 	self.info['STRINGS_IN_RSRCS'] = True
			# 	for string in strings:
			# 		log.info("%s", string)
        else:
			print "[!] No resources found"
			self.info["RSRC"] = None

    def _walk_resources(self,rsrc_dir,depth):
        for entry in rsrc_dir.entries:
            try:
                rsrc_data = entry.data
                print "Lang: %s" % pefile.LANG[rsrc_data.lang]
                print "Size: 0x%08x" % rsrc_data.struct.Size
                return
            except AttributeError:
                if depth == 0:
                    if entry.name:
                        print "Name: %s" % entry.name
                    else:
                        print "Resource ID %s - Type: %s" % (hex(entry.id), pefile.RESOURCE_TYPE[entry.id])
                else:
					if entry.name:
						print "Child Resource Name: %s" %  entry.name
					else:
						print "Child Resource ID:  %s" %  entry.id
            depth += 1
            self._walk_resources(entry.directory,depth)
            depth = depth - 1

    def run(self):

        self._read_pe_info()
        print "--------"

        if (self.impDirEnt.VirtualAddress != 0) and (self.impDirEnt.Size != 0):
            print "[+]IMPORTS"
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                print "\n%s" % entry.dll
                for imp in entry.imports:
                    print "%s\t0x%08x\t%s" % (imp.ordinal, imp.address, imp.name)
            print "--------"

        if (self.expDirEnt.VirtualAddress != 0) and (self.expDirEnt.Size != 0):
            self.exportDir = self._parse_directory_descriptor(self.pe.__IMAGE_EXPORT_DIRECTORY_format__, self.expDirEnt)
            print "[+]DLL NAME\n%s" % self.pe.get_data(self.exportDir.Name).split('\x00')[0]
            print "--------"
            print "[+]EXPORTS\n"
            # print "\n%s\n" % self.exportDir
            addressOfFunctions = self._get_export_addresses()
            exportNames = self._get_export_names()
            fullExports = []
            for indx in xrange(len(addressOfFunctions)):
                fullExports.append((indx+1, addressOfFunctions[indx]+self.pe.OPTIONAL_HEADER.ImageBase, exportNames[indx] if indx < len(exportNames) else "[!]No Export Name" ))
            

            self._print_table(fullExports)

        self._print_verinfo()
        print "--------"
        self._print_debug_data()
        print "--------"
        self._get_signature_info()
        print "--------"
        self._read_resources()

def main():

    parser = argparse.ArgumentParser(description="Show imports and exports of a PE file")
    parser.add_argument('filename', help="Path to executable file to show imports/exports")
    options = parser.parse_args()

    PeInfo(options.filename).run()

if __name__ == '__main__':
    main()
