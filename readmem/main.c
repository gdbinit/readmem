/*
 *  _____           _ _____
 * | __  |___ ___ _| |     |___ _____
 * |    -| -_| .'| . | | | | -_|     |
 * |__|__|___|__,|___|_|_|_|___|_|_|_|
 *
 * A small userland util to dump processes memory
 * Useful to dump stuff or verify stuff without gdb or running under gdb
 *
 * Copyright (c) fG! - 2012, 2013. All rights reserved.
 * reverser@put.as - http://reverse.put.as
 *
 * To compile:
 * gcc -Wall -o readmem readmem.c
 *
 * v0.1 - Initial version
 * v0.2 - Fix the columns output and display memory protection flags
 * v0.3 - Add support to dump the binary image of a mach-o app or library
 *      - Fix unnecessary arm cases
 * v0.4 - Support for ASLR (oops!!!) and fixes to the 64bits (mega ooops!)
 *        Since we have the base address to dump from, we just compute the slide
 *        against the info at the header. Easier than using dyld functions for this.
 *        iOS still has problems dumping libs because of the giant/common __LINKEDIT section!
 * v0.5 - Add function and option to locate and dump main binary
 *        No need to point its address using this option
 * v0.6 - Add option to write to memory
 *
 * Check http://246tnt.com/iPhone/ for iOS Entitlements reference
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include <libkern/OSByteOrder.h>

#define VERSION "0.6"

#define MAX_SIZE 100000000

#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt " (%s, %d)\n", ## __VA_ARGS__, __func__, __LINE__)
#define LOG_BADOPT(fmt, ...) fprintf(stderr, "[BAD OPTION] " fmt "\n", ## __VA_ARGS__)

/* structure for program options */
struct options
{
    uint32_t size;
    pid_t    pid;
    uint8_t  fulldump;
    uint8_t  maindump;
    mach_vm_address_t address;
    uint8_t  writemem;
    uint8_t  *bytes_to_write;
    char     *outputname;
};

/* local functions */
static void header(void);
static void usage(void);
static void get_protection(vm_prot_t protection, char *prot);
static void readmem(mach_vm_offset_t *buffer, mach_vm_address_t address, mach_vm_size_t size, pid_t pid, vm_region_basic_info_data_64_t *info);
static mach_vm_address_t get_image_size(mach_vm_address_t address, pid_t pid);
static void dump_binary(mach_vm_address_t address, pid_t pid, void *buffer);
static kern_return_t find_main_binary(pid_t pid, mach_vm_address_t *main_address);
static void read_memory(struct options *opts);
static void write_memory(struct options *opts);

/* for iOS */
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

extern kern_return_t mach_vm_protect
(
 vm_map_t target_task,
 mach_vm_address_t address,
 mach_vm_size_t size,
 boolean_t set_maximum,
 vm_prot_t new_protection
 );

extern kern_return_t mach_vm_write
(
 vm_map_t target_task,
 mach_vm_address_t address,
 vm_offset_t data,
 mach_msg_type_number_t dataCnt
 );

#endif

/* globals */
mach_vm_address_t vmaddr_slide = 0;

static void 
readmem(mach_vm_offset_t *buffer, mach_vm_address_t address, mach_vm_size_t size, pid_t pid, vm_region_basic_info_data_64_t *info)
{
    // get task for pid
    vm_map_t port = 0;
    kern_return_t kr = 0;
    if (task_for_pid(mach_task_self(), pid, &port))
    {
        LOG_ERROR("Can't execute task_for_pid! Do you have the right permissions/entitlements?");
        exit(1);
    }
    
    mach_msg_type_number_t info_cnt = sizeof (vm_region_basic_info_data_64_t);
    mach_port_t object_name;
    mach_vm_size_t size_info;
    mach_vm_address_t address_info = address;
    kr = mach_vm_region(port, &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &info_cnt, &object_name);
    if (kr)
    {
        LOG_ERROR("mach_vm_region failed with error %d", (int)kr);
        exit(1);
    }

    // read memory - vm_read_overwrite because we supply the buffer
    mach_vm_size_t nread = 0;
    kr = mach_vm_read_overwrite(port, address, size, (mach_vm_address_t)buffer, &nread);

    if (kr)
    {
        LOG_ERROR("vm_read failed! %d", kr);
    }
    else if (nread != size)
    {
        LOG_ERROR("vm_read failed! requested size: 0x%llx read: 0x%llx", size, nread);
    }
}

/*
 * we need to find the binary file size
 * which is taken from the filesize field of each segment command
 * and not the vmsize (because of alignment)
 * if we dump using vmaddresses, we will get the alignment space into the dumped
 * binary and get into problems :-)
 */
static uint64_t
get_image_size(mach_vm_address_t address, pid_t pid)
{
#if DEBUG
    fprintf(stdout, "[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    vm_region_basic_info_data_64_t region_info = {0};
    // allocate a buffer to read the header info
    // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
    // but this will work for this purpose so no need for more complexity!
    struct mach_header header = {0};
    readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), pid, &region_info);

    if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
    {
        LOG_ERROR("Target is not a mach-o binary!");
        exit(1);
    }
    
    uint64_t imagefilesize = 0;
    // read the load commands
    uint8_t *loadcmds = malloc(header.sizeofcmds);
    uint16_t mach_header_size = sizeof(struct mach_header);
    if (header.magic == MH_MAGIC_64)
    {
        mach_header_size = sizeof(struct mach_header_64);
    }
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
            if (strncmp(segCmd->segname, "__PAGEZERO", 16) != 0)
            {
                if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
                {
                    vmaddr_slide = address - segCmd->vmaddr;
                }
                imagefilesize += segCmd->filesize;
            }
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segCmd64 = (struct segment_command_64*)loadCmdAddress;
            if (strncmp(segCmd64->segname, "__PAGEZERO", 16) != 0)
            {
                if (strncmp(segCmd64->segname, "__TEXT", 16) == 0)
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
 * find main binary by iterating memory region
 * assumes there's only one binary with filetype == MH_EXECUTE
 */
static kern_return_t
find_main_binary(pid_t pid, mach_vm_address_t *main_address)
{
  // get task for pid
  vm_map_t target_task = 0;
  kern_return_t kr;
  if (task_for_pid(mach_task_self(), pid, &target_task))
  {
    LOG_ERROR("Can't execute task_for_pid! Do you have the right permissions/entitlements?");
    return KERN_FAILURE;
  }
  
  vm_address_t iter = 0;
  while (1)
  {
      struct mach_header mh = {0};
      vm_address_t addr = iter;
      vm_size_t lsize = 0;
      uint32_t depth;
      mach_vm_size_t bytes_read = 0;
      struct vm_region_submap_info_64 info;
      mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
      if (vm_region_recurse_64(target_task, &addr, &lsize, &depth, (vm_region_info_t)&info, &count))
      {
          break;
      }
      kr = mach_vm_read_overwrite(target_task, (mach_vm_address_t)addr, (mach_vm_size_t)sizeof(struct mach_header), (mach_vm_address_t)&mh, &bytes_read);
      if (kr == KERN_SUCCESS && bytes_read == sizeof(struct mach_header))
      {
          /* only one image with MH_EXECUTE filetype */
          if ( (mh.magic == MH_MAGIC || mh.magic == MH_MAGIC_64) && mh.filetype == MH_EXECUTE)
          {
#if DEBUG
              fprintf(stdout, "[DEBUG] Found main binary mach-o image @ %p!\n", (void*)addr);
#endif
              *main_address = addr;
              break;
          }
      }
      iter = addr + lsize;
  }
  return KERN_SUCCESS;
}

/*
 * dump the binary into the allocated buffer
 * we dump each segment and advance the buffer
 */
static void
dump_binary(mach_vm_address_t address, pid_t pid, void *buffer)
{
#if DEBUG
    fprintf(stdout, "[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    vm_region_basic_info_data_64_t region_info = {0};
    // allocate a buffer to read the header info
    // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
    // but this will work for this purpose so no need for more complexity!
    struct mach_header header = {0};
    readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), pid, &region_info);
    
    if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
    {
		LOG_ERROR("Target is not a mach-o binary!");
        exit(1);
    }
    
    // read the header info to find the LINKEDIT
    uint8_t *loadcmds = malloc(header.sizeofcmds);
    
    uint16_t mach_header_size = sizeof(struct mach_header);
    if (header.magic == MH_MAGIC_64)
    {
        mach_header_size = sizeof(struct mach_header_64);
    }
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
            if (strncmp(segCmd->segname, "__PAGEZERO", 16) != 0)
            {
#if DEBUG
                fprintf(stdout, "[DEBUG] Dumping %s at %llx with size %x (buffer:%x)\n", segCmd->segname, segCmd->vmaddr+vmaddr_slide, segCmd->filesize, (uint32_t)buffer);
#endif
                readmem((mach_vm_offset_t*)buffer, segCmd->vmaddr+vmaddr_slide, segCmd->filesize, pid, &region_info);
            }
            buffer += segCmd->filesize;
        }
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            segCmd64 = (struct segment_command_64*)loadCmdAddress;
            if (strncmp(segCmd64->segname, "__PAGEZERO", 16) != 0)
            {
#if DEBUG
                fprintf(stdout, "[DEBUG] Dumping %s at %llx with size %llx (buffer:%x)\n", segCmd64->segname, segCmd64->vmaddr+vmaddr_slide, segCmd64->filesize, (uint32_t)buffer);
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
	fprintf(stdout,"readmem -p pid [-a address] [-s size] [-o filename] [-f] [-m] [-w] [-b bytes]\n");
	fprintf(stdout,"Available Options : \n");
    fprintf(stdout,"        -a start address\n");
    fprintf(stdout,"        -s dump size\n");
    fprintf(stdout,"        -o filename	file to write binary output to\n");
    fprintf(stdout,"        -f (try do dump whole mach-o binary if start address is valid)\n");
    fprintf(stdout,"        -m (locate and dump main binary)\n");
    fprintf(stdout,"        -w write to memory address instead of reading\n");
    fprintf(stdout,"        -b byte sequence to write (requires size option), maximum 8 bytes\n");
	fprintf(stdout,"Usage:\n");
    fprintf(stdout,"- Read 16 bytes starting at address 0x1000 from PID XX\n");
    fprintf(stdout,"readmem -p XX -a 0x1000 -s 16\n");
    fprintf(stdout,"- Dump Mach-O binary from PID XX located at address 0x1000\n");
    fprintf(stdout,"readmem -p XX -a 0x1000 -o memdump -f\n");
    fprintf(stdout,"- Dump main Mach-O binary of PID XX\n");
    fprintf(stdout,"readmem -p XX -o memdump -m\n");
    fprintf(stdout,"- Write 1 byte INT3 at address 0x1000 from PID XX\n");
    fprintf(stdout,"readmem -p XX -a 0x1000 -s 1 -w -b CC\n");
    fprintf(stdout,"\nNote:\n");
    fprintf(stdout,"The -f option can be used to dump main binary, libraries, bundles, etc\n");
    fprintf(stdout,"The -m option will only dump the main binary.\n");
    fprintf(stdout,"\n");
        
	exit(1);
}

static void
header(void)
{
    fprintf(stdout,"---------------------------------\n");
	fprintf(stdout,"Readmem v%s - (c) 2012, 2013 fG!\n",VERSION);
	fprintf(stdout,"---------------------------------\n\n");
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
        { "main", no_argument, NULL, 'm' },
        { "write", no_argument, NULL, 'w' },
        { "bytes", required_argument, NULL, 'b' },
        { "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int option_index = 0;
    int c = 0;
    
    struct options prog_options = {0};
    prog_options.size = 16; /* make 16bytes the default size */
	// process command line options
	while ((c = getopt_long (argc, argv, "a:s:o:p:fmwb:h", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case ':':
				usage();
				exit(1);
			case '?':
            case 'h':
				usage();
				exit(1);
			case 'o':
				prog_options.outputname = optarg;
				break;
            case 'p':
                prog_options.pid = (pid_t)strtoul(optarg, NULL, 0);
                break;
			case 'a':
				prog_options.address = strtoul(optarg, NULL, 0);
				break;
			case 's':
				prog_options.size = (uint32_t)strtoul(optarg, NULL, 0);
				break;
            case 'f':
                prog_options.fulldump = 1;
                break;
            case 'm':
                prog_options.maindump = 1;
                break;
            case 'w':
                prog_options.writemem = 1;
                break;
            case 'b':
                prog_options.bytes_to_write = (uint8_t*)optarg;
                break;
			default:
				usage();
				exit(1);
		}
	}
	
	header();
    
    if (prog_options.pid == 0)
    {
        LOG_BADOPT("Please add PID argument!\n");
        usage();
    }
    if (prog_options.fulldump && prog_options.address == 0)
    {
        LOG_BADOPT("-f option requires a start address!\n");
        usage();
    }
    if (prog_options.fulldump && prog_options.outputname == NULL)
    {
        LOG_BADOPT("-f option requires an output filename!\n");
        usage();
    }
    if (prog_options.outputname && prog_options.address == 0 && prog_options.maindump == 0)
    {
        LOG_BADOPT("-o option requires a start address!\n");
        usage();
    }
    if (prog_options.maindump && prog_options.outputname == NULL)
    {
        LOG_BADOPT("-m option requires an output filename!\n");
        usage();
    }
    if (prog_options.size > MAX_SIZE || (prog_options.size == 0 && prog_options.fulldump == 0))
    {
        LOG_BADOPT("Invalid size (higher than maximum or zero!)");
        exit(1);
    }
    if (prog_options.writemem && prog_options.bytes_to_write == NULL)
    {
        LOG_BADOPT("Please insert bytes to write!");
        exit(1);
    }
    if (prog_options.outputname == NULL && prog_options.fulldump == 1)
    {
        LOG_BADOPT("Full dump requires output filename!");
        exit(1);
    }
    if (prog_options.writemem && prog_options.size > 8)
    {
        LOG_BADOPT("Maximum allowed size to write is 8 bytes, you chose %d!", prog_options.size);
        exit(1);
    }
    
    /* start doing some real work! */
    if (prog_options.writemem)
    {
        fprintf(stdout, "-[ Memory before writing... ]-\n");
        read_memory(&prog_options);
        write_memory(&prog_options);
        fprintf(stdout, "-[ Memory after writing... ]-\n");
        read_memory(&prog_options);
    }
    else
    {
        read_memory(&prog_options);
    }
    
	return 0;
}

static void
read_memory(struct options *opts)
{
    FILE *outputfile;
	if (opts->outputname != NULL)
	{
		if ( (outputfile = fopen(opts->outputname, "wb")) == NULL)
		{
			LOG_ERROR("Cannot open %s for output!", opts->outputname);
			exit(1);
		}
	}

    uint8_t *readbuffer = NULL;
    if (opts->fulldump == 0)
    {
        readbuffer = malloc(opts->size);
        if (readbuffer == NULL)
        {
            LOG_ERROR("Memory allocation failed!");
            exit(1);
        }
    }
    
    vm_region_basic_info_data_64_t region_info = {0};
	// read memory
    // if it's a full image dump, we need to read its header and find the LINKEDIT segment
    if (opts->fulldump || opts->maindump)
    {
        if (opts->maindump)
        {
            if (find_main_binary(opts->pid, &opts->address))
            {
                LOG_ERROR("Can't find main binary address!");
                exit(1);
            }
        }
        // first we need to find the file size because memory alignment slack spaces
        uint64_t imagesize = 0;
        if ( (imagesize = get_image_size(opts->address, opts->pid)) == 0 )
        {
            LOG_ERROR("Got image file size equal to 0!");
            exit(1);
        }
        // allocate the buffer since size argument is not used
        readbuffer = malloc(imagesize);
        // and finally read the sections and dump their contents to the buffer
        dump_binary(opts->address, opts->pid, (void*)readbuffer);
        // dump buffer contents to file
        if (opts->outputname != NULL)
        {
            if (fwrite(readbuffer, (long)imagesize, 1, outputfile) < 1)
            {
                LOG_ERROR("Write error at %s occurred!", opts->outputname);
                exit(1);
            }
            fprintf(stdout, "\n[OK] Full binary dumped to %s!\n\n", opts->outputname);
        }
    }
    // we just want to read bits'n'pieces!
    else
    {
        readmem((mach_vm_offset_t*)readbuffer, opts->address, opts->size, opts->pid, &region_info);
        // dump to file
        if (opts->outputname != NULL)
        {
            if (fwrite(readbuffer, opts->size, 1, outputfile) < 1)
            {
                LOG_ERROR("Write error at %s occurred!", opts->outputname);
                exit(1);
            }
            fprintf(stdout, "\n[OK] Memory dumped to %s!\n\n", opts->outputname);
        }
        // dump to stdout
        else
        {
            int i = 0;
            int x = 0;
            int z = 0;
            int linelength = 0;
            mach_vm_address_t tmpaddr = opts->address;
            // retrieve memory protection for the region of the starting address
            // CAVEAT: it will be incorrect if dumping size includes more than one region
            //         but we can't get protection per page
            char current_protection[4];
            char maximum_protection[4];
            get_protection(region_info.protection, current_protection);
            get_protection(region_info.max_protection, maximum_protection);
            fprintf(stdout, "Memory protection: %s/%s\n", current_protection, maximum_protection);
            // 16 columns
            while (i < opts->size)
            {
                linelength = (opts->size - i) <= 16 ? (opts->size - i) : 16;
                fprintf(stdout, "%p ",(void*)tmpaddr);
                z = i;
                // hex dump
                for (x = 0; x < linelength; x++)
                {
                    fprintf(stdout, "%02x ", readbuffer[z++]);
                }
                // make it always 16 columns, this could be prettier :P
                for (x = linelength; x < 16; x++)
                {
                    fprintf(stdout, "   ");
                }
                z = i;
                // try to print ascii
                fprintf(stdout, "|");
                for (x = 0; x < linelength; x++)
                {
                    fprintf(stdout, "%c", isascii(readbuffer[z]) && isprint(readbuffer[z]) ? readbuffer[z] : '.');
                    z++;
                }
                i += 16;
                fprintf(stdout, "|\n");
                tmpaddr += 16;
            }
            fprintf(stdout, "\n");
        }
	}
    free(readbuffer);
}

static void
write_memory(struct options *opts)
{
    // get task for pid
    vm_map_t port = 0;
    kern_return_t kr = 0;
    if ( (kr = task_for_pid(mach_task_self(), opts->pid, &port)) )
    {
        LOG_ERROR("Can't execute task_for_pid with error %d! Do you have the right permissions/entitlements?", kr);
        exit(1);
    }
    
    /* get original memory protection */
	mach_vm_size_t size = 0;
	mach_port_t object_name = 0;
     vm_region_basic_info_data_64_t info = {0};
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    /* mach_vm_region will return the address of the map into the address argument so we need to make a copy */
    mach_vm_address_t dummyadr = opts->address;
    if ( (kr = mach_vm_region(port, &dummyadr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name)) )
    {
        LOG_ERROR("mach_vm_region failed with error %d", kr);
        exit(1);
    }
    
    /* change protections, write, and restore original protection */
    task_suspend(port);
    if ( (kr = mach_vm_protect(port, opts->address, (mach_msg_type_number_t)opts->size, FALSE, VM_PROT_WRITE | VM_PROT_READ | VM_PROT_COPY)) )
    {
        LOG_ERROR("mach_vm_protect failed with error %d.", kr);
        exit(1);
    }
    
    /* XXX: input bytes is big endian but it will be written little endian */
    uint64_t bytes = strtoul((char*)opts->bytes_to_write, NULL, 16);
    if ( (kr = mach_vm_write(port, opts->address, (vm_offset_t)&bytes, (mach_msg_type_number_t)opts->size)) )
    {
        LOG_ERROR("mach_vm_write failed at 0x%llx with error %d.", opts->address, kr);
        exit(1);
    }
    /* restore original protection */
    if ( (kr = mach_vm_protect(port, opts->address, (mach_msg_type_number_t)opts->size, FALSE, info.protection)) )
    {
        LOG_ERROR("mach_vm_protect failed with error %d.", kr);
        exit(1);
    }
    task_resume(port);
}
