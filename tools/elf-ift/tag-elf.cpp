#include "elfio/elfio.hpp"
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <string>
#include <sys/random.h>
//#include "xor.h"
//#include "prince.h"
// #include "ascon_auth.h"
using namespace std;

class ElfUtils {
	public:
		ElfUtils(std::string filename) {
			if(!reader.load(filename)) {
				std::cerr << "The file \"" << filename << "\" cannot be opened or is not a valid ELF file" << std::endl;
				exit(1);
			}
		}
      
		void encrypt_file(std::string filename, uint8_t key[16]) {
			create_elf();
            int n = 0;
			int sz = 0;
			uint8_t ntag[200000];
			
			
			for(auto *section : writer.sections) {
				
				size_t size = section->get_size();
				cout<<section->get_name()<<" "<<section->get_type()<<" "<<hex<<section->get_size()<<endl;
				cout<<section->get_address();
				uint8_t *new_data = copy_data((const uint8_t *)section->get_data(), size);
				
	
		#if 1	
		    if(section->get_name()==string(".data")) {
					parse_data(new_data, size, &new_data, ntag);
					sz += size - (size%64);
					printf("sz= %d\n", sz);
					
				}
		#endif	
			//printf("set data done\n");
			//}
			}
	#if 1
    printf("tag section start\n");		
    auto *tag_section = writer.sections.add(".data.tag");
    tag_section->set_addr_align(req_align);
    tag_section->set_address(0x80d00000);
    tag_section->set_type( SHT_PROGBITS);
    tag_section->set_flags( SHF_ALLOC | SHF_WRITE );
    tag_section->set_data((char*)ntag, (sz/64)); //1 bit for 64 bits
	//tag_section->set_data((char*)ntag, 1000); //1 bit for 64 bits
    tag_section->set_size((sz/64));
    printf("tag section done\n");
    #endif
	#if 1
    printf("hash section start\n");	
	 printf("hash section start\n");	
	uint64_t hash_words[4] = {
		0x870BE4A6DD9B87B0ULL,
		0x8679AFA2F002E130ULL,
		0xB7F409BA7EA85E6BULL,
		0xD65C7B3BE62D6E2BULL
	};
    auto *hash_section = writer.sections.add(".data.hash");
    hash_section->set_addr_align(req_align);
    hash_section->set_address(0x80e00000);
    hash_section->set_type( SHT_PROGBITS);
    hash_section->set_flags( SHF_ALLOC );
    hash_section->set_data(reinterpret_cast<const char*>(hash_words),
                       sizeof(hash_words)); //32 bytes = 256
	//tag_section->set_data((char*)ntag, 1000); //1 bit for 64 bits
    hash_section->set_size(sizeof(hash_words));
    printf("hash section done\n");
    #endif
	#if 0
    ELFIO::segment* tag_seg = writer.segments.add();
    tag_seg->set_type( PT_LOAD );
    tag_seg->set_virtual_address( 0x20000);
    tag_seg->set_physical_address( 0x20000);
    tag_seg->set_flags( PF_W | PF_R );
    tag_seg->set_align(req_align);
    tag_seg->add_section_index(tag_section->get_index(), tag_section->get_addr_align());
    printf("tag segment done\n");
	 writer.set_entry(0x100e8);
    writer.save(filename);
#endif	
     writer.save(filename);
		}

		

	private:
		ELFIO::elfio reader;
		ELFIO::elfio writer;

		uint8_t master_key = 159;
		const uint64_t req_align = 0x1000;

		void create_elf() {
			writer.create(reader.get_class(), reader.get_encoding(), reader.sections.size());
			writer.set_abi_version(reader.get_abi_version());
			writer.set_os_abi(reader.get_os_abi());
			writer.set_machine(reader.get_machine());
			writer.set_type(reader.get_type());
			writer.set_flags(reader.get_flags());
			writer.set_section_name_str_index(reader.get_section_name_str_index());

			for(auto *old_section : reader.sections) {
				auto *section = writer.sections[old_section->get_index()];

				section->set_name(old_section->get_name());
				section->set_name_string_offset(old_section->get_name_string_offset());
				section->set_type(old_section->get_type());
				section->set_flags(old_section->get_flags());
				section->set_info(old_section->get_info());
				section->set_link(old_section->get_link());
				section->set_entry_size(old_section->get_entry_size());
				
				// section->set_addr_align(std::max((ELFIO::Elf_Xword) 1, old_section->get_addr_align()));
				section->set_address(old_section->get_address());  // Explicitly set sh_addr
                section->set_addr_align(old_section->get_addr_align());
				section->set_data(old_section->get_data(), old_section->get_size());
			}

			for(auto *old_segment : reader.segments) {
				auto *segment = writer.segments.add();
				
				segment->set_type(old_segment->get_type());
				segment->set_flags(old_segment->get_flags());

				
				segment->set_virtual_address (old_segment->get_virtual_address());
				segment->set_physical_address(old_segment->get_physical_address());
				segment->set_file_size       (old_segment->get_file_size());    // p_filesz
				segment->set_memory_size     (old_segment->get_memory_size());  // p_memsz
				segment->set_align(old_segment->get_align()); 

				for(ELFIO::Elf_Half i = 0; i < old_segment->get_sections_num(); i++) {
					auto section_ndx = old_segment->get_section_index_at(i);
					// segment->add_section_index(section_ndx, 0);
					auto* sec = writer.sections[section_ndx];
        			segment->add_section_index(section_ndx, sec->get_addr_align());
				}
			}

			  writer.set_entry(reader.get_entry());

		}

		uint8_t *copy_data(const uint8_t *old_data, size_t size) {
			//printf("copy data\n");
			uint8_t *new_data = (uint8_t *) calloc(1, size);
			if(old_data != NULL) {
				memcpy(new_data, old_data, size);
			}
			else{
				cout<<"Hello\n";
			}
			return new_data;
		}
        
        void parse_data(uint8_t *data, size_t size, uint8_t **ret_data, uint8_t *ntag) {
				printf("reached parse data\n");
				
				long tag_ind = 0;
				int bit_val = 0;
				ntag[0] = 0;
				for(size_t i = 0; i < (size)/8; i++) {  //tag each 8 byte (64-bit) of data; size is in bytes
						//long tag_ind = curpos >> 3;
						printf("value of i = %d\n", i);
					    //tagging all data as 1 for now
						//ntag[tag_ind] = 1;        //is 84 the default tag value?
					                              //some bitwise operation is needed to store 1 bit tag here
					    bit_val = (ntag[tag_ind] << 1) + 1;
				        ntag[tag_ind] =  bit_val;
                        printf("ntag[%d] = %d\n", tag_ind, ntag[tag_ind]);
					//curpos += 8;
					if(bit_val == 255){
                        tag_ind += 1;
						bit_val = 0;
						ntag[tag_ind] = 0;
					}
					    
					
				}	 
				//*pos = *pos + size;
				//*ret_data = data;  
				
				
}

		
};


int main(int argc, char *argv[]) {

  if (argc != 2) {
    printf("./enc <elfname>\n");
	  return 0;
  }
	std::string filename(argv[1]);
    
	uint8_t key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ElfUtils(filename).encrypt_file(filename + ".kg", key);

	return 0;
}
