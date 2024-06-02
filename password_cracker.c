#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

// Predefined key range for MD5 hashing
const char *key_range[] = {
    "D76AA478", "E8C7B756", "242070DB", "C1BDCEEE", "F57C0FA", "4787C62A", "A8304613", "FD469501",
    "698098D8", "8B44F7AF", "FFFF5BB1", "895CD7BE", "6B901122", "FD987193", "A679438E", "49B40821",
    "F61E2562", "C040B340", "265E5A51", "E9B6C7AA", "D62F105D", "02441453", "D8A1E681", "E7D3FBC8",
    "21E1CDE6", "C33707D6"
};

// Function to calculate MD5 hash with a given key
void md5_with_key_range(const char *input, const char *key, char outputBuffer[33]) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Error: EVP_MD_CTX_new() failed\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        fprintf(stderr, "Error: EVP_DigestInit_ex() failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(mdctx, input, strlen(input)) != 1) {
        fprintf(stderr, "Error: EVP_DigestUpdate() failed for input\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(mdctx, key, strlen(key)) != 1) {
        fprintf(stderr, "Error: EVP_DigestUpdate() failed for key\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    unsigned char digest[MD5_DIGEST_LENGTH];
    unsigned int digest_len;
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        fprintf(stderr, "Error: EVP_DigestFinal_ex() failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&outputBuffer[i * 2], 3, "%02x", digest[i]);
    }
    outputBuffer[32] = '\0';

    EVP_MD_CTX_free(mdctx);
}

// Function to generate MD5 hash for user input
void generate_hash_for_user_input(const char *input, char outputBuffer[33]) {
    md5_with_key_range(input, "", outputBuffer);
}

// Function to process the dictionary file
int process_dictionary(const char *filename, const char *user_input, int is_hashed) {
    FILE *dictionary = fopen(filename, "r");
    if (dictionary == NULL) {
        perror("Error opening dictionary file");
        return 0;
    }

    char str[200];
    char hashed_input[33];
    int found = 0;

    while (fgets(str, sizeof(str), dictionary) != NULL) {
        str[strcspn(str, "\n")] = 0;  // Remove newline character

        if (is_hashed) {
            char *token = strtok(str, ":");
            if (token != NULL) {
                char *hash = strtok(NULL, ":");
                if (hash != NULL) {
                    printf("Comparing: dictionary='%s', generated='%s'\n", hash, user_input);

                    if (strcmp(hash, user_input) == 0) {
                        found = 1;
                        printf("Match found! Entry: '%s'\n", str);
                        break;
                    }
                } else {
                    printf("Invalid dictionary entry: '%s'\n", str);
                }
            } else {
                printf("Invalid dictionary entry: '%s'\n", str);
            }
        } else {
            for (int i = 0; i < sizeof(key_range) / sizeof(key_range[0]); i++) {
                md5_with_key_range(str, key_range[i], hashed_input);
                printf("Comparing: dictionary='%s', generated='%s'\n", hashed_input, user_input);

                if (strcmp(hashed_input, user_input) == 0) {
                    found = 1;
                    printf("Match found! Username: '%s', Key: '%s'\n", str, key_range[i]);
                    break;
                }
            }
            if (found) break;
        }
    }

    fclose(dictionary);
    return found;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <dictionary_path> <is_hashed (0 or 1)> <user_input> <is_input_hashed (0 or 1)>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *dictionary_path = argv[1];
    int is_hashed = atoi(argv[2]);
    const char *input = argv[3];
    int is_input_hashed = atoi(argv[4]);
    char user_input[33];

    // Generate hash for plain text user input
    if (is_input_hashed) {
        strncpy(user_input, input, 33);
    } else {
        generate_hash_for_user_input(input, user_input);
    }

    // Process the dictionary file
    int found = process_dictionary(dictionary_path, user_input, is_hashed);

    if (!found) {
        printf("No match found.\n");
    }

    return EXIT_SUCCESS;
}
