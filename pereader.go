package main 

import (
	"fmt"
	"debug/pe"
	"os"
)

type DOSHeader struct {
	Signature,				
	Offset		[]byte			
}

func (hdr *DOSHeader) getValues(f *os.File) {
	buf := make([]byte, 64)
	f.Read(buf)
	hdr.Signature = swapValue(buf[0:2])
	if hdr.Signature[0] != 0x5a || hdr.Signature[1] != 0x4d {
		fmt.Println()
		fmt.Println("[!] Error: Invalid file!")
		os.Exit(2)
	}
	hdr.Offset = swapValue(buf[60:])
}

type OptionalHeader struct {
	Magic, 						
	MajorLinkerVersion, 		
    MinorLinkerVersion, 		
	SizeOfCode, 				
	SizeOfInitializedData,		
	SizeOfUninitializedData,	
	AddressOfEntryPoint,		
	BaseOfCode,					
	BaseOfData,					
	ImageBase,					
	SectionAlignment,			
	FileAlignment,				
	MajorOperatingSystemVersion,
	MinorOperatingSystemVersion,
	MajorImageVersion,			
	MinorImageVersion,			
	MajorSubsystemVersion,		
	MinorSubsystemVersion,
	Win32VersionValue,			
	SizeOfImage,				
	SizeOfHeaders,				
	CheckSum,					
	Subsystem,					
	DllCharacteristics,			
	SizeOfStackReserve,			
	SizeOfStackCommit,			
	SizeOfHeapReserve,			
	SizeOfHeapCommit,			
	LoaderFlags,				
	NumberOfRvaAndSizes			[]byte		
}

func (hdr *OptionalHeader) getValues(f *os.File, size int, offset int) {
	buf := make([]byte, size)
	f.ReadAt(buf, int64(offset + 24))
	hdr.Magic = swapValue(buf[:2])
	hdr.MajorLinkerVersion = swapValue(buf[2:3])
	hdr.MinorLinkerVersion = swapValue(buf[3:4])
	hdr.SizeOfCode = swapValue(buf[4:8])
	hdr.SizeOfInitializedData = swapValue(buf[8:12])
	hdr.SizeOfUninitializedData = swapValue(buf[12:16])
	hdr.AddressOfEntryPoint = swapValue(buf[16:20])
	hdr.BaseOfCode = swapValue(buf[20:24])
	hdr.BaseOfData = swapValue(buf[24:28])
	hdr.ImageBase = swapValue(buf[28:32])
	hdr.SectionAlignment = swapValue(buf[32:36])
	hdr.FileAlignment = swapValue(buf[36:40])
	hdr.MajorOperatingSystemVersion = swapValue(buf[40:42])
	hdr.MinorOperatingSystemVersion = swapValue(buf[42:44])
	hdr.MajorImageVersion = swapValue(buf[44:46])
	hdr.MinorImageVersion = swapValue(buf[46:48])
	hdr.MajorSubsystemVersion = swapValue(buf[48:50])
	hdr.MinorSubsystemVersion = swapValue(buf[50:52])
	hdr.Win32VersionValue = swapValue(buf[52:56])
	hdr.SizeOfImage = swapValue(buf[56:60])
	hdr.SizeOfHeaders = swapValue(buf[60:64])
	hdr.CheckSum = swapValue(buf[64:68])
	hdr.Subsystem = swapValue(buf[68:70])
	hdr.DllCharacteristics = swapValue(buf[70:72])
	hdr.SizeOfStackReserve = swapValue(buf[72:76])
	hdr.SizeOfStackCommit = swapValue(buf[76:80])
	hdr.SizeOfHeapReserve = swapValue(buf[80:84])
	hdr.SizeOfHeapCommit = swapValue(buf[84:88])
	hdr.LoaderFlags = swapValue(buf[88:92])
	hdr.NumberOfRvaAndSizes = swapValue(buf[92:96])
}

func swapValue(val []byte) ([]byte) {
	if len(val) > 1 {
		for i := 0; i < (len(val)-1); i = i+2 {
			val = swap(val, i, i+1)
		}
		if len(val) == 4 {
			tmp := make([]byte, 0, len(val))
			for _, v := range val[2:] {
				tmp = append(tmp, v)
			}
			for _, v := range val[:2] {
				tmp = append(tmp, v)
			}
			val = tmp
		}
	}
	return val	
}

func chkErr(err error) {
	if err != nil {
		fmt.Println()
		fmt.Println("[!] Fehler: ", err)
		os.Exit(2)
	}
}

func convToInt(slice []byte) (dec int) {
	s := fmt.Sprintf("%x", slice)
	dec = 0
	base := 1
	for i := (len(s)-1); i >= 0; i-- {
		if s[i] <= 57 && s[i] >= 48 {
			tmp := int(s[i]) - 48
			dec = dec + (tmp * base)
			base = base * 16
		}
		if s[i] <= 66 && s[i] >= 61 {
			tmp := int(s[i]) - 51
			dec = dec + (tmp * base)
			base = base * 16
		} 
	}  
	return
}

func swap(slice []byte, pos1, pos2 int) (newslice []byte) {
	newslice = make([]byte, len(slice))
	newslice = slice
	if len(slice) > 1 {
		newslice[pos1], newslice[pos2] = slice[pos2], slice[pos1]
	}
	return
}

func printDOSHdr(doshdr DOSHeader) {
	fmt.Println()
	fmt.Println("DOS Header:")
	fmt.Println()
	fmt.Printf(" Signature:\t\t 0x%x\n", doshdr.Signature)
	fmt.Printf(" Offset:\t\t 0x%x\n", doshdr.Offset)
}

func printFileHdr(file *pe.File) {
	fmt.Println()
	fmt.Println("File Header:")
	fmt.Println()
	fmt.Printf(" Machine:\t\t %#x \n", file.FileHeader.Machine)
	fmt.Printf(" NumberOfSections:\t %d \n", file.FileHeader.NumberOfSections)
	fmt.Printf(" TimeDateStamp:\t\t %#x \n", file.FileHeader.TimeDateStamp)
	fmt.Printf(" PointerToSymbolTable:\t %#x \n", file.FileHeader.PointerToSymbolTable)
	fmt.Printf(" NumberOfSymbols:\t %#x \n", file.FileHeader.NumberOfSymbols)
	fmt.Printf(" SizeOfOptionalHeader:\t %#x \n", file.FileHeader.SizeOfOptionalHeader)
	fmt.Printf(" Characteristics:\t %#x \n", file.FileHeader.Characteristics)
	fmt.Println()
}

func printOptHdr(opthdr OptionalHeader) {
	fmt.Println()
	fmt.Println("Optional Header:")
	fmt.Println()
	fmt.Printf(" Magic:\t\t\t\t 0x%x \n", opthdr.Magic)
	fmt.Printf(" MajorLinkerVersion:\t\t 0x%x \n", opthdr.MajorLinkerVersion)
	fmt.Printf(" MinorLinkerVersion:\t\t 0x%x \n", opthdr.MinorLinkerVersion)
	fmt.Printf(" SizeOfCode:\t\t\t 0x%x \n", opthdr.SizeOfCode)
	fmt.Printf(" SizeOfInitializedData:\t\t 0x%x \n", opthdr.SizeOfInitializedData)
	fmt.Printf(" SizeOfUninitializedData:\t 0x%x \n", opthdr.SizeOfUninitializedData)
	fmt.Printf(" AddressOfEntryPoint:\t\t 0x%x \n", opthdr.AddressOfEntryPoint)
	fmt.Printf(" BaseOfCode:\t\t\t 0x%x \n", opthdr.BaseOfCode)
	fmt.Printf(" BaseOfData:\t\t\t 0x%x \n", opthdr.BaseOfData)
	fmt.Printf(" ImageBase:\t\t\t 0x%x \n", opthdr.ImageBase)
	fmt.Printf(" SectionAlignment:\t\t 0x%x \n", opthdr.SectionAlignment)
	fmt.Printf(" FileAlignment:\t\t\t 0x%x \n", opthdr.FileAlignment)
	fmt.Printf(" MajorOperatingSystemVersion:\t 0x%x \n", opthdr.MajorOperatingSystemVersion)
	fmt.Printf(" MinorOperatingSystemVersion:\t 0x%x \n", opthdr.MinorOperatingSystemVersion)
	fmt.Printf(" MajorImageVersion:\t\t 0x%x \n", opthdr.MajorImageVersion)
	fmt.Printf(" MinorImageVersion:\t\t 0x%x \n", opthdr.MinorImageVersion)
	fmt.Printf(" MajorSubsystemVersion:\t\t 0x%x \n", opthdr.MajorSubsystemVersion)
	fmt.Printf(" MinorSubsystemVersion:\t\t 0x%x \n", opthdr.MinorSubsystemVersion)
	fmt.Printf(" Win32VersionValue:\t\t 0x%x \n", opthdr.Win32VersionValue)
	fmt.Printf(" SizeOfImage:\t\t\t 0x%x \n", opthdr.SizeOfImage)
	fmt.Printf(" SizeOfHeaders:\t\t\t 0x%x \n", opthdr.SizeOfHeaders)
	fmt.Printf(" CheckSum:\t\t\t 0x%x \n", opthdr.CheckSum)
	fmt.Printf(" Subsystem:\t\t\t 0x%x \n", opthdr.Subsystem)
	fmt.Printf(" DllCharacteristics:\t\t 0x%x \n", opthdr.DllCharacteristics)
	fmt.Printf(" SizeOfStackReserve:\t\t 0x%x \n", opthdr.SizeOfStackReserve)
	fmt.Printf(" SizeOfStackCommit:\t\t 0x%x \n", opthdr.SizeOfStackCommit)
	fmt.Printf(" SizeOfHeapReserve:\t\t 0x%x \n", opthdr.SizeOfHeapReserve)
	fmt.Printf(" SizeOfHeapCommit:\t\t 0x%x \n", opthdr.SizeOfHeapCommit)
	fmt.Printf(" LoaderFlags:\t\t\t 0x%x \n", opthdr.LoaderFlags)
	fmt.Printf(" NumberOfRvaAndSizes:\t\t 0x%x \n", opthdr.NumberOfRvaAndSizes)
}

func printSecAll(file *pe.File) {
	for _, sec := range file.Sections {
		fmt.Println()
		fmt.Println("Section Header for ", sec.Name, ": ")
		fmt.Println()
		fmt.Printf(" Name:\t\t\t%s\n", sec.Name)
		fmt.Printf(" VirtualSize:\t\t %#x\n", sec.VirtualSize)
		fmt.Printf(" VirtualAddress:\t %#x\n", sec.VirtualAddress)
		fmt.Printf(" SizeOfRawData:\t\t %#x\n", sec.Size)
		fmt.Printf(" PointerToRawData:\t %#x\n", sec.Offset)
		fmt.Printf(" PointerToRelocations:\t %#x\n", sec.PointerToRelocations)
		fmt.Printf(" PointerToLinenumbers:\t %#x\n", sec.PointerToLineNumbers)
		fmt.Printf(" NumberOfRelocations:\t %#x\n", sec.NumberOfRelocations)
		fmt.Printf(" NumberOfLinenumbers:\t %#x\n", sec.NumberOfLineNumbers)
		fmt.Printf(" Characteristics:\t %#x\n", sec.Characteristics)
		fmt.Println()
	}
}

func printUsage() {
	fmt.Println()
	fmt.Println("[!] Usage: pereader.exe <target file> <option>")
	fmt.Println("[+] Options:")
	fmt.Println("\t-F\tshow File Header")
	fmt.Println("\t-O\tshow Optional Header")
	fmt.Println("\t-S\tshow all Section Headers")
	fmt.Println()
	fmt.Println("[+] Note: only one option is allowed")
	fmt.Println()
}

func main() {
	if len(os.Args) <= 2 || len(os.Args) >= 4 {
		printUsage()
	} else {
		switch os.Args[2] {
			case "-F":
				file, err := pe.Open(os.Args[1])
				chkErr(err)
				
				printFileHdr(file)
				
				err = file.Close()
				chkErr(err)
			case "-O":
				file, err := pe.Open(os.Args[1])
				chkErr(err)
				
				f, err := os.Open(os.Args[1])
				chkErr(err)
				
				doshdr := DOSHeader{}
				doshdr.getValues(f)
				
				opthdr := OptionalHeader{}
				opthdr.getValues(f, int(file.FileHeader.SizeOfOptionalHeader), convToInt(doshdr.Offset))
				
				printOptHdr(opthdr)
				
				err = f.Close()
				chkErr(err)
				
				err = file.Close()
				chkErr(err)
			case "-S":
				file, err := pe.Open(os.Args[1])
				chkErr(err)
				
				printSecAll(file)
				
				err = file.Close()
				chkErr(err)
			default:
				printUsage()
		}
	}
}

