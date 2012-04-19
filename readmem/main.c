/*
 * Readmem
 *
 * A small userland util to dump processes memory
 * Useful to dump stuff or verify stuff without gdb or running under gdb
 *
 * (c) fG! - 2012 - reverser@put.as - http://reverse.put.as
 *
 * To compile:
 * gcc -Wall -o readkmem readkmem.c
 *
 * v0.1 - Initial version
 * v0.2 - Fix the columns output and display memory protection flags
 * v0.3 - Add support to dump the binary image of a mach-o app or library
 *      - Fix unnecessary arm cases
 * v0.4 - Support for ASLR (oops!!!) and fixes to the 64bits (mega ooops!)
 *        Since we have the base address to dump from, we just compute the slide
 *        against the info at the header. Easier than using dyld functions for this.
 *        iOS still has problems dumping libs because of the giant/common __LINKEDIT section!
 *
 * Check http://246tnt.com/iPhone/ for iOS Entitlements reference
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <getopt.h>
#include <ctype.h>
#include <mach/mach.h> 
#if !defined (__arm__)
#include <mach/mach_vm.h>
#endif
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>

#define VERSION "0.4"

#define MAX_SIZE 100000000

// prototypes
static void header(void);
static void usage(void);
static void get_protection(vm_prot_t protection, char *prot);
static void readmem(mach_vm_offset_t *buffer, mach_vm_address_t address, mach_vm_size_t size, pid_t pid, vm_region_basic_info_data_64_t *info);
static mach_vm_address_t get_image_size(mach_vm_address_t address, pid_t pid);
static void dump_binary(mach_vm_address_t address, pid_t pid, void *buffer);

// for iOS
#if defined (__arm__)
extern kern_return_t mach_vm_region
(
 vm_map_t target_task,
 mach_vm_address_t *address,
 mach_vm_size_t *size,
 vm_region_flavor_t flavor,
 vm_region_info_t info,
 mach_msg_type_number_t *infoCnt,
 mach_port_t *object_name
 );

extern kern_return_t mach_vm_read_overwrite
(
 vm_map_t target_task,
 mach_vm_address_t address,
 mach_vm_size_t size,
 mach_vm_address_t data,
 mach_vm_size_t *outsize
 );
#endif

mach_vm_address_t vmaddr_slide = 0;

static void 
readmem(mach_vm_offset_t *buffer, mach_vm_address_t address, mach_vm_size_t size, pid_t pid, vm_region_basic_info_data_64_t *info)
{
    // get task for pid
    vm_map_t port;

    kern_return_t kr;
//#if DEBUG
//    printf("[DEBUG] Readmem of address %llx to buffer %llx with size %llx\n", address, buffer, size);
//#endif
    if (task_for_pid(mach_task_self(), pid, &port))
    {
        fprintf(stderr, "[ERROR] Can't execute task_for_pid! Do you have the right permissions/entitlements?\n");
        exit(1);
    }
    
    mach_msg_type_number_t info_cnt = sizeof (vm_region_basic_info_data_64_t);
    mach_port_t object_name;
    mach_vm_size_t size_info;
    mach_vm_address_t address_info = address;
    kr = mach_vm_region(port, &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &info_cnt, &object_name);
    if (kr)
    {
        fprintf(stderr, "[ERROR] mach_vm_region failed with error %d\n", (int)kr);
        exit(1);
    }

    // read memory - vm_read_overwrite because we supply the buffer
    mach_vm_size_t nread;

    kr = mach_vm_read_overwrite(port, address, size, (mach_vm_address_t)buffer, &nread);

    if (kr || nread != size)
    {
        fprintf(stderr, "[ERROR] vm_read failed! %d\n", kr);
        exit(1);
    }
}

/*
 * we need to find the binary file size
 * which is taken from the filesize field of each segment command
 * and not the vmsize (because of alignment)
 * if we dump using vmaddresses, we will get the alignment space into the dumped
 * binary and get into problems :-)
 */
static mach_vm_address_t get_image_size(mach_vm_address_t address, pid_t pid)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    vm_region_basic_info_data_64_t region_info;
    // allocate a buffer to read the header info
    // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
    // but this will work for this purpose so no need for more complexity!
    struct mach_header header;
    readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), pid, &region_info);

    if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
    {
		printf("[ERROR] Target is not a mach-o binary!\n");
        exit(1);
    }
    
    mach_vm_address_t imagefilesize = 0;
    
    // read the load commands
    uint8_t *loadcmds = malloc(header.sizeofcmds*sizeof(uint8_t));
    uint16_t mach_header_size = 0;
    if (header.magic == MH_MAGIC)
        mach_header_size = sizeof(struct mach_header);
    else if (header.magic == MH_MAGIC_64)
        mach_header_size = sizeof(struct mach_header_64);

    readmem((mach_vm_offset_t*)loadcmds, address+mach_header_size, header.sizeofcmds, pid, &region_info);
    
    // process and retrieve address and size of linkedit
    uint8_t *loadCmdAddress = 0;
    // first load cmd address
    loadCmdAddress = (uint8_t*)loadcmds;
    struct load_command *loadCommand    = NULL;
    struct segment_command *segCmd      = NULL;
    struct segment_command_64 *segCmd64 = NULL;
    // process commands to find the info we need
    for (uint32_t i = 0; i < header.ncmds; i++)
    {
        loadCommand = (struct load_command*)loadCmdAddress;
        // 32bits and 64 bits segment commands
        // LC_LOAD_DYLIB to find the ordinal
        if (loadCommand->cmd == LC_SEGMENT)
        {
            segCmd = (struct segment_command*)loadCmdAddress;
            if (strcmp((char*)(segCmd->segname), "__PAGEZERO") != 0)
            {
                if (strcmp((char*)(segCmd->segname), "__TEXT") == 0)
                {
                    vmaddr_slide = address - segCmd->vmaddr;
                }
//#if DEBUG
//                printf("[DEBUG] %s %x\n", segCmd->segname, segCmd->filesize);
//#endif
                imagefilesize += segCmd->filesize;
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segCmd64 = (struct segment_command_64*)loadCmdAddress;
            if (strcmp((char*)(segCmd64->segname), "__PAGEZERO") != 0)
            {
                if (strcmp((char*)(segCmd64->segname), "__TEXT") == 0)
                {
                    vmaddr_slide = address - segCmd64->vmaddr;
                }

                imagefilesize += segCmd64->filesize;
            }
        }
        // advance to next command
        loadCmdAddress += loadCommand->cmdsize;
    }
    free(loadcmds);
    return imagefilesize;
}


/*
 * dump the binary into the allocated buffer
 * we dump each segment and advance the buffer
 */
static void dump_binary(mach_vm_address_t address, pid_t pid, void *buffer)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    vm_region_basic_info_data_64_t region_info;
    // allocate a buffer to read the header info
    // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
    // but this will work for this purpose so no need for more complexity!
    struct mach_header header;
    readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), pid, &region_info);
    
    if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
    {
		printf("[ERROR] Target is not a mach-o binary!\n");
        exit(1);
    }
    
    // read the header info to find the LINKEDIT
    uint8_t *loadcmds = malloc(header.sizeofcmds*sizeof(uint8_t));
    
    uint16_t mach_header_size = 0;
    if (header.magic == MH_MAGIC)
        mach_header_size = sizeof(struct mach_header);
    else if (header.magic == MH_MAGIC_64)
        mach_header_size = sizeof(struct mach_header_64);
    // retrieve the load commands
    readmem((mach_vm_offset_t*)loadcmds, address+mach_header_size, header.sizeofcmds, pid, &region_info);
    
    // process and retrieve address and size of linkedit
    uint8_t *loadCmdAddress = 0;
    // first load cmd address
    loadCmdAddress = (uint8_t*)loadcmds;
    struct load_command *loadCommand    = NULL;
    struct segment_command *segCmd      = NULL;
    struct segment_command_64 *segCmd64 = NULL;
    // process commands to find the info we need

    for (uint32_t i = 0; i < header.ncmds; i++)
    {
        loadCommand = (struct load_command*)loadCmdAddress;
        // 32bits and 64 bits segment commands
        // LC_LOAD_DYLIB to find the ordinal
        if (loadCommand->cmd == LC_SEGMENT)
        {
            segCmd = (struct segment_command*)loadCmdAddress;
            if (strcmp((char*)(segCmd->segname), "__PAGEZERO") != 0)
            {
#if DEBUG
                printf("[DEBUG] Dumping %s at %llx with size %x (buffer:%x)\n", segCmd->segname, segCmd->vmaddr+vmaddr_slide, segCmd->filesize, (uint32_t)buffer);
#endif
                readmem((mach_vm_offset_t*)buffer, segCmd->vmaddr+vmaddr_slide, segCmd->filesize, pid, &region_info);
            }
            buffer += segCmd->filesize;
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segCmd64 = (struct segment_command_64*)loadCmdAddress;
            if (strcmp((char*)(segCmd64->segname), "__PAGEZERO") != 0)
            {
#if DEBUG
                printf("[DEBUG] Dumping %s at %llx with size %llx (buffer:%x)\n", segCmd64->segname, segCmd64->vmaddr+vmaddr_slide, segCmd64->filesize, (uint32_t)buffer);
#endif
                readmem((mach_vm_offset_t*)buffer, segCmd64->vmaddr+vmaddr_slide, segCmd64->filesize, pid, &region_info);
            }
            buffer += segCmd64->filesize;
        }
        // advance to next command
        loadCmdAddress += loadCommand->cmdsize;
    }
    free(loadcmds);
}

/*
 * get an ascii representation of memory protection
 */
static void 
get_protection(vm_prot_t protection, char *prot)
{
    prot[0] = protection & 1 ? 'r' : '-';
    prot[1] = protection & (1 << 1) ? 'w' : '-';
    prot[2] = protection & (1 << 2) ? 'x' : '-';
    prot[3] = '\0';
}

static void
usage(void)
{
	fprintf(stderr,"readmem -p pid -a address -s size [-o filename] [-f]\n");
	fprintf(stderr,"Available Options : \n");
	fprintf(stderr,"       -o filename	file to write binary output to\n");
    fprintf(stderr,"       -f           make a full dump of target binary\n");
	exit(1);
}

static void
header(void)
{
	fprintf(stderr,"[ Readmem v%s - (c) fG! ]\n",VERSION);
	fprintf(stderr,"--------------------------\n");
}


int 
main(int argc, char ** argv)
{
    
	// required structure for long options
	static struct option long_options[]={
        { "pid", required_argument, NULL, 'p' },
		{ "address", required_argument, NULL, 'a' },
		{ "size", required_argument, NULL, 's' },
		{ "out", required_argument, NULL, 'o' },
        { "full", no_argument, NULL, 'f' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0;
    int c = 0;
	char *outputname = NULL;
	
    uint32_t size     = 0;
    pid_t    pid      = 0;
    uint8_t  fulldump = 0;

	mach_vm_address_t address = 0;

	// process command line options
	while ((c = getopt_long (argc, argv, "a:s:o:p:f", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case ':':
				usage();
				exit(1);
				break;
			case '?':
				usage();
				exit(1);
				break;
			case 'o':
				outputname = optarg;
				break;
            case 'p':
                pid = (pid_t)strtoul(optarg, NULL, 0);
                break;
			case 'a':
				address = strtoul(optarg, NULL, 0);
				break;
			case 's':
				size = (uint32_t)strtoul(optarg, NULL, 0);
				break;
            case 'f':
                fulldump = 1;
                break;
			default:
				usage();
				exit(1);
		}
	}
	
	header();
    
	if (argc < 7)
	{
		usage();
	}
    
    if (size > MAX_SIZE || (size == 0 && fulldump == 0))
    {
        printf("[ERROR] Invalid size (higher than maximum or zero!)\n");
        exit(1);
    }
    
    uint8_t *readbuffer = NULL;
    if (fulldump == 0)
    {
        readbuffer = malloc(size*sizeof(uint8_t));
        if (readbuffer == NULL)
        {
            printf("[ERROR] Memory allocation failed!\n");
            exit(1);
        }
    }
    
	FILE *outputfile;	
	if (outputname != NULL)
	{
		if ( (outputfile = fopen(outputname, "wb")) == NULL)
		{
			fprintf(stderr,"[ERROR] Cannot open %s for output!\n", outputname);
			exit(1);
		}
	}
	
    if (outputname == NULL && fulldump == 1)
    {
        printf("[ERROR] Full dump requires output filename!\n");
        exit(1);
    }
    
    vm_region_basic_info_data_64_t region_info;
	// read memory
    // if it's a full image dump, we need to read its header and find the LINKEDIT segment
    if (fulldump)
    {
        // first we need to find the file size because memory alignment slack spaces
        mach_vm_address_t imagesize = 0;
        imagesize = get_image_size(address, pid);
        // reallocate the buffer since size argument is not used
        readbuffer = malloc((long)imagesize * sizeof(uint8_t));
        // and finally read the sections and dump their contents to the buffer
        dump_binary(address, pid, (void*)readbuffer);
        // dump buffer contents to file
        if (outputname != NULL)
        {
            if (fwrite(readbuffer, (long)imagesize, 1, outputfile) < 1)
            {
                fprintf(stderr,"[ERROR] Write error at %s occurred!\n", outputname);
                exit(1);
            }
            printf("\n[OK] Full binary dumped to %s!\n\n", outputname);
        }
    }
    // we just want to read bits'n'pieces!
    else
    {
        readmem((mach_vm_offset_t*)readbuffer, address, size, pid, &region_info);
        // dump to file
        if (outputname != NULL)
        {
            if (fwrite(readbuffer, size, 1, outputfile) < 1)
            {
                fprintf(stderr,"[ERROR] Write error at %s occurred!\n", outputname);
                exit(1);
            }
            printf("\n[OK] Memory dumped to %s!\n\n", outputname);
        }
        // dump to stdout
        else
        {
            int i = 0;
            int x = 0;
            int z = 0;
            int linelength = 0;
            
            // retrieve memory protection for the region of the starting address
            // CAVEAT: it will be incorrect if dumping size includes more than one region
            //         but we can't get protection per page
            char current_protection[4]; 
            char maximum_protection[4];
            get_protection(region_info.protection, current_protection);
            get_protection(region_info.max_protection, maximum_protection);
            printf("Memory protection: %s/%s\n\n", current_protection, maximum_protection);
            // 16 columns
            while (i < size)
            {
                linelength = (size - i) <= 16 ? (size - i) : 16;
                printf("%p ",(void*)address);
                z = i;
                // hex dump
                for (x = 0; x < linelength; x++)
                {
                    printf("%02x ", readbuffer[z++]);
                }
                // make it always 16 columns, this could be prettier :P
                for (x = linelength; x < 16; x++)
                    printf("   ");
                z = i;
                // try to print ascii
                for (x = 0; x < linelength; x++)
                {
                    printf("%c", isascii(readbuffer[z]) && isprint(readbuffer[z]) ? readbuffer[z] : '.');
                    z++;
                }
                i += 16;
                printf("\n");
                address += 16;
            }
            printf("\n");	
        }
	}
    free(readbuffer);
	return 0;
}

