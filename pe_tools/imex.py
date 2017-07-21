/*
 * @Author: Pengwinsurf 
 * @Date: 2017-07-21 16:08:49 
 * @Last Modified by:   Pengwinsurf 
 * @Last Modified time: 2017-07-21 16:08:49 
 */
import argparse
import pefile
import os


class IMEX():

    def __init__(self, filePath):
        self.pe = pefile.PE(os.path.abspath(filePath))
        self.expDirEnt = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        self.impDirEnt = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]


    def _print_table(self, table):
        """ Helper function to print tables. 
        Columns are Ordinal , VA, ExportName
        """

        for item in table:
            print "%d\t0x%08x\t%s" % (item[0], item[1], item[2])


    def _parse_directory_descriptor(self, structType, dirEntry):
        """ Will parse the directory entry given a VA and size returning an instance of the 
            directory descriptor
        """
        
        return self.pe.__unpack_data__(structType, self.pe.get_data( dirEntry.VirtualAddress, pefile.Structure(structType).sizeof() ), file_offset = self.pe.get_offset_from_rva(dirEntry.VirtualAddress) )

    def _get_export_addresses(self):
        """ Will walk the Function Table Addresses and return a list 
            of each VA. 
        """
        offset = 0 
        exportAddresses = []
        for x in xrange(self.exportDir.NumberOfFunctions):
            exportAddresses.append(self.pe.get_dword_at_rva(self.exportDir.AddressOfFunctions+offset))
            offset = offset + 4

        return exportAddresses

    def _get_export_names(self):
        """ Based on the number of names in the Export Directory descriptor,
         return all export names
        """ 
        offset = 0 
        exportNames = []
        for x in xrange(self.exportDir.NumberOfNames):
            nameAddress = self.pe.get_dword_at_rva(self.exportDir.AddressOfNames+offset)
            exportNames.append(self.pe.get_data(nameAddress).split('\x00')[0])
            offset = offset + 4

        return exportNames

    def run(self):

        if (self.impDirEnt.VirtualAddress != 0) and (self.impDirEnt.Size != 0):
            print "\nImports:"
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                print "\n%s" % entry.dll
                for imp in entry.imports:
                    print "%s\t0x%08x\t%s" % (imp.ordinal, imp.address, imp.name)

        if (self.expDirEnt.VirtualAddress != 0) and (self.expDirEnt.Size != 0):
            self.exportDir = self._parse_directory_descriptor(self.pe.__IMAGE_EXPORT_DIRECTORY_format__, self.expDirEnt)
            print "\nExports: "
            print "\n%s\n" % self.exportDir
            addressOfFunctions = self._get_export_addresses()
            exportNames = self._get_export_names()
            fullExports = []
            for indx in xrange(len(addressOfFunctions)):
                fullExports.append((indx+1, addressOfFunctions[indx]+self.pe.OPTIONAL_HEADER.ImageBase, exportNames[indx] if indx < len(exportNames) else "No Export Name" ))
            

            self._print_table(fullExports)

def main():

    parser = argparse.ArgumentParser(description="Show imports and exports of a PE file")
    parser.add_argument('filename', help="Path to executable file to show imports/exports")
    options = parser.parse_args()

    IMEX(options.filename).run()

if __name__ == '__main__':
    main()