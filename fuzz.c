#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct tar_t
{                              /* byte offset */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */
    char devminor[8];             /* 337 */
    char prefix[155];             /* 345 */
    char padding[12];             /* 500 */
};



/**
 * Computes the checksum for a tar header and encode it on the header
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_t* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

void generate_fuzzed_tar_header(struct tar_t *header, int test_case) {
    memset(header, 0, sizeof(struct tar_t)); // Clear memory

    // Basic valid tar header
    strcpy(header->name, "fuzz.txt");
    strcpy(header->mode, "0000777");
    strcpy(header->uid, "0001750");
    strcpy(header->gid, "0001750");
    strcpy(header->size, "00000000000");
    strcpy(header->mtime, "00000000000");
    header->typeflag = '0';
    strcpy(header->linkname, "");
    strcpy(header->magic, "ustar"); // Ensure correct magic value
    strcpy(header->version, "00");  // Ensure correct version
    strcpy(header->uname, "user");
    strcpy(header->gname, "group");
    strcpy(header->devmajor, "000");
    strcpy(header->devminor, "000");
    strcpy(header->prefix, "");

    switch(test_case) {
        case 1:
            strcpy(header->size, "0000000144");
            break;
        case 3:
            // Invalid link name
            header->typeflag = '1'; // Indicate this is a link
            for (int i = 0; i < 100; i++) {
                header->linkname[i] = 'a'; // Invalid link name
            }
            header->linkname[99] = '\0'; // Null-terminate the link name
            break;
    }

    // Calculate the checksum after introducing variations
    calculate_checksum(header);
}

// Function to write fuzzed tar files
char* write_fuzzed_tar_file(int test_case) {
    struct tar_t header;
    char filename[64];

    // Generate a filename based on the test case
    snprintf(filename, sizeof(filename), "archive%d.tar", test_case);

    if (test_case == 7) {
        // Change the filename to include special characters
        snprintf(filename, sizeof(filename), "archive_@#$%^&éè¨$.tar");
    }

    generate_fuzzed_tar_header(&header, test_case);

    FILE *fp = fopen(filename, "wb");
    if (fp != NULL) {
        fwrite(&header, sizeof(header), 1, fp); // Write the header
        // If you have file data to write, do it here
        if (test_case == 0) {
            // Unexpected EOF case: write less data than header size
            char data[100] = {0}; // Assuming header size is more than 100
            fwrite(data, sizeof(data), 1, fp);
        }
        if (test_case == 4) {
            // Write less data than expected for the header
            fwrite(&header, sizeof(header) - 1, 1, fp);
        }
        
        if (test_case == 5) {
            char data[100];
            // Invalid file content
            for (int i = 0; i < 100; i++) {
                data[i] = (char)0xFF; // Invalid character
            }
        }
        if (test_case == 6){
            //2 file in the archive
            struct tar_t header2;
            memset(&header2, 0, sizeof(struct tar_t));
            snprintf(header2.name, sizeof(header2.name), "fuzz2.txt");
            snprintf(header2.mode, sizeof(header2.mode), "%07o", 0644);
            snprintf(header2.size, sizeof(header2.size), "%011o", 10);
            strcpy(header2.magic, "ustar");
            strcpy(header2.version, "00");
            calculate_checksum(&header2); // Calculate checksum for the second header
            
            // Write the second header
            fwrite(&header2, sizeof(struct tar_t), 1, fp);
            // Write the content of the second file
            const char* content2 = "Hi, file2!\n";
            size_t content_size2 = strlen(content2);
            fwrite(content2, content_size2, 1, fp);
            // If needed, add padding to make the tar file multiple of 512 bytes
            size_t remaining_bytes2 = (sizeof(struct tar_t) + content_size2) % 512;
            if (remaining_bytes2 != 0) {
                char padding[512] = {0};
                fwrite(padding, 512 - remaining_bytes2, 1, fp);
            }
        }
        fclose(fp);
        return strdup(filename);
    }
    return NULL;
}

void write_tar_file() {
    struct tar_t header;
    memset(&header, 0, sizeof(header)); // Initialize header with zeros
    // Populate header fields
    strcpy(header.name, "dummy.txt");
    header.typeflag = '0'; // Regular file
    strcpy(header.magic, "ustar"); // Fill the magic field
    strcpy(header.version, "00");  // Fill the version field
    strcpy(header.uname, "user"); // Fill the uname field
    strcpy(header.gname, "group"); // Fill the gname field

    calculate_checksum(&header); // Calculate and set the checksum

    FILE *fp = fopen("example.tar", "wb");
    if (fp != NULL) {
        fwrite(&header, sizeof(header), 1, fp); // Write the header
        // If you have file data to write, do it here
        fclose(fp);
    }
}


/**
 * Launches another executable given as argument,
 * parses its output and check whether or not it matches "*** The program has crashed ***".
 * @param the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 *
 * BONUS (for fun, no additional marks) without modifying this code,
 * compile it and use the executable to restart our computer.
 */
int main(int argc, char* argv[])
{
    const int num_test_cases = 9; // Adjust based on how many cases you have
    for (int i = 0; i < num_test_cases; ++i) {
        char* filename = write_fuzzed_tar_file(i);
        if (filename == NULL) {
            printf("Error during the generation of the archive %d\n", i);
            continue;
        }
        // Code to run the custom extractor on the generated tar file and check for crashes

        char cmd[51];
        snprintf(cmd, sizeof(cmd), "%s %s", argv[1], filename); 

        char buf[33];
        FILE *fp;

        if ((fp = popen(cmd, "r")) == NULL) {
            printf("Error opening pipe!\n");
            return -1;
        }
        
        printf("Running command: %s\n", cmd);
        if(fgets(buf, 33, fp) == NULL) {
            printf("No output\n");
            goto finally;
        }
        printf("Output: %s\n", buf);
        if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
            printf("Not the crash message\n");
            goto finally;
        } else {
            printf("Crash message\n");
            // rv = 1; // Uncomment this line if you want to set rv to 1 on crash
            char new_filename[64];
            snprintf(new_filename, sizeof(new_filename), "success_archive%d.tar", i);
            if (rename(filename, new_filename) != 0) {
                printf("Erreur lors du renommage du fichier.\n");
            }
            goto finally;
        }
        finally:
        if(pclose(fp) == -1) {
            printf("Command not found\n");
            // rv = -1; // Uncomment this line if you want to set rv to -1 on command not found
        }
    }

    if (argc < 2)
        return -1;

    printf("Running %s\n", argv[1]);
    int rv = 0;
    return rv;
}