#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *plain_hash_str = md5(plaintext, strlen(plaintext));
    // Open the hash file
    FILE *hash_file = fopen(hashFilename, "r");

    char line_buffer[HASH_LEN + 2];
    char *match_hash = NULL;

    if (hash_file == NULL)
    {

        perror("Error opening hash file.\n");
        exit(1);   
    }
    // Loop through the hash file, one line at a time.
    while (fgets(line_buffer, sizeof(line_buffer), hash_file))
    {
        line_buffer[strcspn(line_buffer, "\n")] = '\0';
        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(plain_hash_str, line_buffer) == 0 )
        {
            match_hash = (char *)malloc(HASH_LEN);
            if (match_hash)
            {
                strcpy(match_hash, line_buffer);
            }
            break;
        }
    }

    fclose(hash_file);

    free(plain_hash_str);

    return match_hash;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    char *hash_filename = argv[1];
    char *dict_filename = argv[2];

    char line_buffer[PASS_LEN + 2];

    FILE *dict_file = fopen(dict_filename, "r");
    if (dict_file == NULL)
    {
        perror("Error opening dict file.\n");
        exit(1);
    }
    int crackCount = 0;
    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    while (fgets(line_buffer, sizeof(line_buffer), dict_file))
    {
        line_buffer[strcspn(line_buffer, "\n")] = '\0';

        char *found = tryWord(line_buffer, hash_filename);
        if (found)
        {
            printf("%s %s\n", found, line_buffer);
            crackCount++;
            free(found);
        }
    }
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello
    
    // Close the dictionary file.
    fclose(dict_file);
    // Display the number of hashes that were cracked.
    printf("Cracked %d Hashes\n", crackCount);
    // Free up any malloc'd memory?
}

