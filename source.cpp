#include <iostream>
#include <windows.h>
#include <winnt.h>
#include <fstream>
#include <vector>
#include <stdexcept>

using namespace std;

struct Section {
    string name;
    uint64_t virtualAddress;
    uint64_t virtualSize;
    uint64_t sizeOfRawData;
    uint64_t pointerToRawData;
};

vector<Section> parseSections(ifstream& peFile, uint32_t numberOfSections, uint32_t sectionHeadersOffset);
void fileOffset(uint64_t fileOffset, uint64_t imageBase, const vector<Section>& sections);
void rva(uint64_t rva, uint64_t imageBase, const vector<Section>& sections);
void va(uint64_t va, uint64_t imageBase);

int main() {
    string filePath;

    cout << "Enter the path to the executable: ";
    cin >> filePath;

    ifstream peFile(filePath, ios::binary);
    if (!peFile) {
        cerr << "Unable to open file: " << filePath << endl;
        return 1;
    }

    IMAGE_DOS_HEADER dosHeader;
    peFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    /*if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "Not a valid PE file" << endl;
        return 1;
    }*/

    peFile.seekg(dosHeader.e_lfanew, ios::beg);

    IMAGE_NT_HEADERS32 ntHeader32;
    IMAGE_NT_HEADERS64 ntHeader64;

    peFile.read(reinterpret_cast<char*>(&ntHeader32), sizeof(ntHeader32));

   /* if (ntHeader32.Signature != IMAGE_NT_SIGNATURE) {
        cerr << "Not a valid PE file" << endl;
        return 1;
    }*/

    uint64_t imageBase;
    uint32_t numberOfSections;
    uint32_t sectionHeadersOffset;

    // to handle 32bit and 64bit applicationn
    if (ntHeader32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { 
        peFile.seekg(dosHeader.e_lfanew, ios::beg);
        peFile.read(reinterpret_cast<char*>(&ntHeader64), sizeof(ntHeader64));
        imageBase = ntHeader64.OptionalHeader.ImageBase;
        numberOfSections = ntHeader64.FileHeader.NumberOfSections;
        sectionHeadersOffset = dosHeader.e_lfanew + sizeof(ntHeader64);
    }
    else if (ntHeader32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        imageBase = ntHeader32.OptionalHeader.ImageBase;
        numberOfSections = ntHeader32.FileHeader.NumberOfSections;
        sectionHeadersOffset = dosHeader.e_lfanew + sizeof(ntHeader32);
    }
    else {
        cerr << "Unknown optional header format" << endl;
        return 1;
    }

    //cout << hex << imageBase << endl;

    vector<Section> sections = parseSections(peFile, numberOfSections, sectionHeadersOffset);

    /*for (const auto& section : sections) {
        cout << "Section: " << section.name << endl;
        cout << "  Virtual Address: 0x" << hex << section.virtualAddress << endl;
        cout << "  Virtual Size: 0x" << hex << section.virtualSize << endl;
        cout << "  Size of Raw Data: 0x" << hex << section.sizeOfRawData << endl;
        cout << "  Pointer to Raw Data: 0x" << hex << section.pointerToRawData << endl;
    }*/

    int choice;
    uint64_t inputValue;

    cout << "Select your desired input value:" << endl;
    cout << "1. File Offset" << '\n';
    cout << "2. RVA" << '\n';
    cout << "3. VA" << '\n';
    cin >> choice;

    cout << "Enter the value (in hexadecimal): ";
    cin >> hex >> inputValue;

    try {
        switch (choice) {
        case 1:
            fileOffset(inputValue, imageBase, sections);
            break;
        case 2:
            rva(inputValue, imageBase, sections);
            break;
        case 3:
            va(inputValue, imageBase);
            break;
        default:
            cout << "Invalid choice!" << endl;
        }
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
    }
    system("PAUSE");
    return 0;
}

vector<Section> parseSections(ifstream& peFile, uint32_t numberOfSections, uint32_t sectionHeadersOffset) {
    vector<Section> sections;
    peFile.seekg(sectionHeadersOffset, ios::beg);

    for (uint32_t i = 0; i < numberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        peFile.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));

        Section section;
        section.name = string(reinterpret_cast<char*>(sectionHeader.Name), 8);
        section.virtualAddress = sectionHeader.VirtualAddress;
        section.virtualSize = sectionHeader.Misc.VirtualSize;
        section.sizeOfRawData = sectionHeader.SizeOfRawData;
        section.pointerToRawData = sectionHeader.PointerToRawData;
        sections.push_back(section);
    }

    return sections;
}

void fileOffset(uint64_t fileOffset, uint64_t imageBase, const vector<Section>& sections) {
    // Check if file offset is less than the start of the first section's raw data
    if (!sections.empty() && fileOffset < sections[0].pointerToRawData) {
        cout << "File Offset: 0x" << hex << fileOffset << "\nRVA: 0x" << fileOffset << "\nVA: 0x" << fileOffset + imageBase << endl;
        return;
    }

    for (const auto& section : sections) {
        if (fileOffset >= section.pointerToRawData && fileOffset < section.pointerToRawData + section.sizeOfRawData) {
            uint64_t sectionOffset = fileOffset - section.pointerToRawData;
            uint64_t rva = section.virtualAddress + sectionOffset;
            uint64_t va = imageBase + rva;
            cout << "File Offset: 0x" << hex << fileOffset << "\nRVA: 0x" << rva << "\nVA: 0x" << va << endl;
            return;
        }
    }
    throw runtime_error("File offset does not belong to any section");
}

void rva(uint64_t rva, uint64_t imageBase, const vector<Section>& sections) {
    for (const auto& section : sections) {
        if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
            uint64_t sectionOffset = rva - section.virtualAddress;
            uint64_t fileOffset = section.pointerToRawData + sectionOffset;
            uint64_t va = imageBase + rva;
            cout << "RVA: 0x" << hex << rva << "\nFile Offset: 0x" << fileOffset << "\nVA: 0x" << va << endl;
            return;
        }
    }
    throw runtime_error("RVA does not belong to any section");
}

void va(uint64_t va, uint64_t imageBase) {
    if (va < imageBase) {
        cout << "VA: 0x" << va << "\nRVA: 0x" << "00000000" << endl;
    }
    uint64_t rva = va - imageBase;
    cout << "VA: 0x" << hex << va << "\nRVA: 0x" << rva << endl;
}
