#!/usr/bin/python

""" Script to extract information from a PE file """

import argparse
import os
import binascii


import pefile
from M2Crypto import *

__author__ = "Pengwinsurf"
__copyright__ = "Copyright 2017"
__license__ = "MIT"
__version__ = "0.2"
__date__ = "22 July 2017"


class PeInfo():

    def __init__(self, filePath):
        self.filePath = os.path.abspath(filePath)
        self.pe = pefile.PE(os.path.abspath(filePath))
        self.expDirEnt = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        self.impDirEnt = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]

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

        print "\nVERSION INFORMATION"
        if hasattr(self.pe, 'FileInfo'):
            for fileInfo in self.pe.FileInfo:
                if fileInfo.Key == 'StringFileInfo':
                    for vInfo in fileInfo.StringTable:
                        for info in vInfo.entries.items():
                            print "%s:\t%s" % (info[0], info[1])
        else:
            print "No Version Information"
        print "--------"

    def __print_debug_data(self):
        """ Print out Debug data if present """
        print "\nDEBUG INFO"

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
                        print "PDB file: %s" % raw_pdb.split('\x00')[0].encode('utf-8')

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
                        print "PDB file: %s" % raw_pdb.split('\x00')[0].encode('utf-8')

            except AttributeError, KeyError:
                pass


        print "--------"


    def _get_signature_info(self):
        """ Check if a PE is signed and get information about the signature
        """

        print "\nCertificate information"
        securityDir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]

        if (securityDir.VirtualAddress == 0 and securityDir.Size == 0):
            print "No Authenticode found"
            return 

        offset = self.pe.get_offset_from_rva(securityDir.VirtualAddress)


        with open(self.filePath, 'rb') as fh:
            fh.seek(offset)
            sig = fh.read(securityDir.Size)


        with open('temp.sig', 'wb+') as fh:
            fh.write(sig[8:])

        p7 = SMIME.load_pkcs7_der('temp.sig')

        signers = p7.get0_signers(X509.X509_Stack())

        for cert in signers:
            print "Issuer: %s " % cert.get_issuer().as_text()
            print "Not After: %s " % cert.get_not_after()
            print "Subject: %s " % cert.get_subject().as_text()

    def run(self):

        if (self.impDirEnt.VirtualAddress != 0) and (self.impDirEnt.Size != 0):
            print "\nIMPORTS"
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                print "\n%s" % entry.dll
                for imp in entry.imports:
                    print "%s\t0x%08x\t%s" % (imp.ordinal, imp.address, imp.name)
            print "--------"

        if (self.expDirEnt.VirtualAddress != 0) and (self.expDirEnt.Size != 0):
            self.exportDir = self._parse_directory_descriptor(self.pe.__IMAGE_EXPORT_DIRECTORY_format__, self.expDirEnt)
            print "\nDLL NAME\n%s" % self.pe.get_data(self.exportDir.Name).split('\x00')[0]
            print "--------"
            print "\nEXPORTS\n"
            # print "\n%s\n" % self.exportDir
            addressOfFunctions = self._get_export_addresses()
            exportNames = self._get_export_names()
            fullExports = []
            for indx in xrange(len(addressOfFunctions)):
                fullExports.append((indx+1, addressOfFunctions[indx]+self.pe.OPTIONAL_HEADER.ImageBase, exportNames[indx] if indx < len(exportNames) else "No Export Name" ))
            

            self._print_table(fullExports)

        self._print_verinfo()

        self.__print_debug_data()

        self._get_signature_info()

def main():

    parser = argparse.ArgumentParser(description="Show imports and exports of a PE file")
    parser.add_argument('filename', help="Path to executable file to show imports/exports")
    options = parser.parse_args()

    PeInfo(options.filename).run()

if __name__ == '__main__':
    main()
