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
        //uint8_t ntag[1000];
		//uint8_t ntag[10];
		void encrypt_file(std::string filename, uint8_t key[16]) {
			create_elf();
            int n = 0;
			int sz = 0;
			uint8_t ntag[200000];
			//uint8_t* ntag = (uint8_t *) calloc(1, 5000);
			
			for(auto *section : writer.sections) {
				
				size_t size = section->get_size();
				cout<<section->get_name()<<" "<<section->get_type()<<" "<<hex<<section->get_size()<<endl;
				cout<<section->get_address();
				uint8_t *new_data = copy_data((const uint8_t *)section->get_data(), size);
				/*if(section->get_type()==8 && (section->get_name()==string(".sbss") || 
                    section->get_name()==string(".bss") || section->get_name()==string("__libc_freeres_ptrs") || section->get_name()==string(".rodata1")
					 || section->get_name()==string(".fini"))){
					section->set_type(1);
				}*/
				// if(section->get_type()==8 && (section->get_name()==string(".sbss") || 
                //     section->get_name()==string(".bss"))){
				// 	section->set_type(1);
				// }
				/*if(section->get_name()==string(".rodata"))
				   print_data(new_data, size, key);*/
#if 0
				if(section->get_type()==8 && (section->get_name()==string(".tbss"))) {
					section->set_type(1);
        }
#endif
           // if(section->get_name()==string(".text") || section->get_name()==string(".rodata") || section->get_name()==string(".data") || section->get_name()==string(".sdata") || section->get_name()==string(".sbss") || section->get_name()==string(".bss") || section->get_name()==string(".eh_frame") || section->get_name()==string(".init_array") || section->get_name()==string(".fini_array")){
				//printf("if block\n");
				// sz += size - (size%64);
				#if 0
				if (section->get_name() == ".sdata") {
					size_t size = section->get_size();
					const uint8_t* data = (const uint8_t*)section->get_data();

					cout << ".sdata section contents (" << size << " bytes):" << endl;
					for (size_t i = 0; i < size; i++) {
						printf("%02x ", data[i]);
						if ((i + 1) % 16 == 0)  // New line every 16 bytes
							printf("\n");
					}
					printf("\n");
				}
				#endif
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
	char * hash = 0;	//add computed hash of binary here
    auto *hash_section = writer.sections.add(".data.hash");
    hash_section->set_addr_align(req_align);
    hash_section->set_address(0x80e00000);
    hash_section->set_type( SHT_PROGBITS);
    hash_section->set_flags( SHF_ALLOC | SHF_WRITE );
    hash_section->set_data(hash, 32); //32 bytes = 256
	//tag_section->set_data((char*)ntag, 1000); //1 bit for 64 bits
    hash_section->set_size((sz/64));
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

				// segment->set_align(std::max((ELFIO::Elf_Xword) 1, old_segment->get_align()));
				// segment->set_align(old_segment->get_align());
				// segment->set_virtual_address(old_segment->get_virtual_address());  
				// segment->set_physical_address(old_segment->get_physical_address());    

				// segment->set_offset          (old_segment->get_offset());       // p_offset
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
				//printf("contents of section: %x\n", data);
				//size_t offs = 0, curpos = *pos;
				// if(size%8!=0)
				//    size = size + (8-(size%8));  //otherwise last few bytes will be left out, size should be multiple of 8
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

		// void crypt_data(uint8_t *data, size_t size, uint8_t **p, uint8_t key[16], uint8_t *ntag, int *n) {
		// 	//printf("reached crypt data\n");
		// 	size_t size_al;
		// 	if(size%64 != 0){
		// 		    size_al = size + (64 - (size%64));
		// 			//printf("not 64\n");
					
		// 	}
		// 	else
		// 	   size_al = size;

		// 	uint8_t *aligned = (uint8_t *) calloc(1, size_al);
		// 	        memcpy(aligned, data , size);
		// 	        for(size_t i = size; i < size_al/64; i++)  //i < size_al??
		// 	             aligned[i] = 0;
		// 	printf("%x\n", size_al);
		// 	uint8_t *ciphertext = (uint8_t *) calloc(1, size_al);
		// 	uint8_t *temp2 = (uint8_t *) calloc(1, size_al);
		// 	//uint8_t *aligned = (uint8_t *) calloc(1, size);
		// 	//memcpy(aligned, data , size - (64 - (size%64)));
		// 	//for(size_t i = size - (64 - (size%64)); i < size/64; i++)
		// 	       // aligned[i] = 0;
			
		// 	uint8_t *message = (uint8_t *) calloc(1, 64); //store 64 bits= 8bytes at a time  //64 bytes???
		// 	uint8_t *block = (uint8_t *) calloc(1, 8); // encrypt 64 bits at a time
        //     uint8_t *temp_block = (uint8_t *) calloc(1, 8);
		// 	uint8_t *temp_msg = (uint8_t *) calloc(1, 64);
		// 	srand(time(NULL));
		// 	//printf("mem alloc done\n");
		// 	for(size_t i = 0; i < (size_al)/64; i++) {
				
		// 		//generate a random nonce for every 56 byte block
				
        //         // Generate four 8-bit random numbers and combine them to get a 32-bit random number
        //         uint32_t nonce = 0;
        //         for (int i = 0; i < 4; i++) {
        //           nonce = (nonce << 8) | (rand() & 0xFF);
        //         }
		// 	    //printf("nonce: %x\n", nonce);
		// 		if(size%64!=0)
		// 		   memcpy(message, aligned + (i*64) , 64);
		// 	    else
		// 		   memcpy(message, data + (i*64) , 64);
                
		// 		for(size_t j = 0; j < 64; j += 8) {
		// 		   memcpy(block, message + j , 8);
		// 		   //reverse(message, &message);
				   
		// 		   //uint8_t *temp_block = (uint8_t *) calloc(1, 8);
				   
		// 	       for(int i=0; i<8; i++){
		// 		      temp_block[i] = block[7-i];
		// 	       }
		// 		   //0x4c4b45f1
		// 		//    ascon_encrypt(temp_block,key,ciphertext + (i*64 + j), 0, 8);
		// 	       /*printf("pt:"); 
        //            for(int k = 0; k < 8; k++)
		// 		      printf("%02x", temp_block[k]);
        //             printf("\n");
			                                                                                                                                                                  
		// 	      printf("ct:");  
		// 		  for(int k = 0; k < 8; k++)
		// 		      printf("%02x", (ciphertext+(i*64 + j))[k]);  
		// 		  printf("\n");*/
		// 	       //printf("enc done\n"); 
		//         for(int m=0; m<8; m++){
		// 		   (temp2+(i*64 + j))[m] = (ciphertext+(i*64 + j))[7-m];
		// 	    }

		// 		if(j == 56){
		// 			for(int k = 0; k < 8; k++){
		// 		       ntag[*n + k] = (ciphertext+(i*64 + j))[k+8];
		// 			   //ntag[0] = (ciphertext+(i*64 + j))[k+8];
		// 			   //printf("%d\n", *n);
		// 	    }
		// 		//printf("tag set : %d\n", *n);
		// 		*n += 8;
		// 		/*printf("nonce and tag in prog:");
		// 		for(int k = 0; k < 8; k++){
		// 		   printf("%x", ntag[*n - 8 + k]);
		// 	    }
		// 		printf("\n");*/
		// 		}  //last 8 byte block 
		// 	}
			
		// 	//reverse(message, &message);
		// 		//uint8_t *temp_msg = (uint8_t *) calloc(1, 64);
		// 	 /*
		// 	    for(int i=0; i<64; i++){
		// 		   temp_msg[i] = message[63-i];
		// 	    }
				
		// 		ascon_encrypt(temp_msg,key,ciphertext + (i*64), nonce, 64);
				

		// 		//set nonce and tag
		// 	    for(int k = 0; k < 8; k++){
		// 		   ntag[*n + k] = (ciphertext+(i*64))[k+64];
		// 	    }
				
		// 		*n += 8;
				
		// 		/*printf("nonce and tag in prog:");
		// 		for(int k = 0; k < 8; k++){
		// 		   printf("%x", ntag[*n - 8 + k]);
		// 	    }
		// 		printf("\n"); */
	        

		
		// }
		
		// *p = temp2;
		
				   
		// }
};


int main(int argc, char *argv[]) {

  if (argc != 2) {
    printf("./enc <elfname>\n");
	  return 0;
  }
	std::string filename(argv[1]);
    //uint8_t key[8] = {0x08, 0x4c, 0x2a, 0x6e, 0x19, 0x5d, 0x3b, 0x7f};
	//uint8_t key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x4c, 0x2a, 0x6e, 0x19, 0x5d, 0x3b, 0x7f};
	uint8_t key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	//uint8_t key[8] = {0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f};
	//ElfUtils(filename).encrypt_file(filename + ".enc", atoi(argv[2]));
    ElfUtils(filename).encrypt_file(filename + ".enc", key);

	return 0;
}
