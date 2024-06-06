#include<iostream>
#include<windows.h>
#include<winnt.h>
#include<fstream>
#include<vector>
#include<stdexcept>

using namespace std;

const char* filePath = "C:\\Windows\\notepad.exe";

struct Section {
    string name;
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
};

void fileOffset(uint32_t fileOffset, uint32_t imageBase, const vector<Section>& sections);
void rva(uint32_t rva, uint32_t imageBase, const vector<Section>& sections);
void va(uint32_t va, uint32_t imageBase);

int main() {
    ifstream peFile(filePath, ios::binary);
    if (!peFile) {
        cerr << "Unable to open file: " << filePath << endl;
        return 1;
    }

    IMAGE_DOS_HEADER dosHeader;
    peFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "Not a valid PE file" << endl;
        return 1;
    }

    peFile.seekg(dosHeader.e_lfanew, ios::beg);

    IMAGE_NT_HEADERS ntHeader;
    peFile.read(reinterpret_cast<char*>(&ntHeader), sizeof(ntHeader));

    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        cerr << "Not a valid PE file" << endl;
        return 1;
    }

    auto imageBase = ntHeader.OptionalHeader.ImageBase;

    vector<Section> sections;
    IMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; ++i) {
        peFile.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
        Section section;
        section.name = string(reinterpret_cast<char*>(sectionHeader.Name), 8);
        section.virtualAddress = sectionHeader.VirtualAddress;
        section.virtualSize = sectionHeader.Misc.VirtualSize;
        section.sizeOfRawData = sectionHeader.SizeOfRawData;
        section.pointerToRawData = sectionHeader.PointerToRawData;
        sections.push_back(section);
    }

    int choice;
    uint32_t inputValue;

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

    return 0;
}

void fileOffset(uint32_t fileOffset, uint32_t imageBase, const vector<Section>& sections) {
    // Check if file offset is less than the start of the .text section
    if (!sections.empty() && fileOffset < sections[0].pointerToRawData) {
        cout << "File Offset: 0x" << hex << fileOffset << "\nRVA: 0x" << fileOffset << "\nVA: 0x" << fileOffset + imageBase << endl;
        return;
    }

    for (const auto& section : sections) {
        if (fileOffset >= section.pointerToRawData && fileOffset < section.pointerToRawData + section.sizeOfRawData) {
            uint32_t sectionOffset = fileOffset - section.pointerToRawData;
            uint32_t rva = section.virtualAddress + sectionOffset;
            uint32_t va = imageBase + rva;
            cout << "File Offset: 0x" << hex << fileOffset << "\nRVA: 0x" << rva << "\nVA: 0x" << va << endl;
            return;
        }
    }
    throw runtime_error("File offset does not belong to any section");
}

void rva(uint32_t rva, uint32_t imageBase, const vector<Section>& sections) {
    for (const auto& section : sections) {
        if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
            uint32_t sectionOffset = rva - section.virtualAddress;
            uint32_t fileOffset = section.pointerToRawData + sectionOffset;
            uint32_t va = imageBase + rva;
            cout << "RVA: 0x" << hex << rva << "\nFile Offset: 0x" << fileOffset << "\nVA: 0x" << va << endl;
            return;
        }
    }
    throw runtime_error("RVA does not belong to any section");
}

void va(uint32_t va, uint32_t imageBase) {
    uint32_t rva = va - imageBase;
    cout << "VA: 0x" << hex << va << "\nRVA: 0x" << rva << endl;
}
