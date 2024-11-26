#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

// Predefined key range for salting the hash
const char *key_range[] = {
    "D76AA478", "E8C7B756", "242070DB", "C1BDCEEE", "F57C0FA", "4787C62A",
    "A8304613", "FD469501", "698098D8", "8B44F7AF", "FFFF5BB1", "895CD7BE",
    "6B901122", "FD987193", "A679438E", "49B40821", "F61E2562", "C040B340",
    "265E5A51", "E9B6C7AA", "D62F105D", "02441453", "D8A1E681", "E7D3FBC8",
    "21E1CDE6", "C33707D6"
};

// ANSI color codes for enhanced terminal output
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

// Function to calculate MD5 hash with optional salting
void compute_md5(const char *input, const char *key, char output[33]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, RED "Error: Unable to create EVP_MD_CTX\n" RESET);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
        fprintf(stderr, RED "Error: Digest initialization failed\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
        fprintf(stderr, RED "Error: Digest update failed for input\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (key && strlen(key) > 0) {
        if (EVP_DigestUpdate(ctx, key, strlen(key)) != 1) {
            fprintf(stderr, RED "Error: Digest update failed for key\n" RESET);
            EVP_MD_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }

    unsigned char hash[MD5_DIGEST_LENGTH];
    if (EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        fprintf(stderr, RED "Error: Digest finalization failed\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        snprintf(&output[i * 2], 3, "%02x", hash[i]);
    }
    output[32] = '\0';

    EVP_MD_CTX_free(ctx);
}

// Function to process the dictionary file
int process_dictionary(const char *filename, const char *user_hash, int is_hashed) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror(RED "Error opening dictionary file" RESET);
        return 0;
    }

    char line[256];
    char generated_hash[33];
    int found = 0;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';  // Remove newline character

        if (is_hashed) {
            if (strcmp(line, user_hash) == 0) {
                found = 1;
                printf(GREEN "Match found! Hash: '%s'\n" RESET, line);
                break;
            }
        } else {
            for (int i = 0; i < sizeof(key_range) / sizeof(key_range[0]); ++i) {
                compute_md5(line, key_range[i], generated_hash);

                if (strcmp(generated_hash, user_hash) == 0) {
                    found = 1;
                    printf(GREEN "Match found! Entry: '%s', Key: '%s'\n" RESET, line, key_range[i]);
                    break;
                }
            }
        }

        if (found) break;
    }

    fclose(file);
    return found;
}

void print_usage(const char *program_name) {
    printf(YELLOW "Usage: %s <dictionary_path> <is_hashed (0 or 1)> <user_input> <is_input_hashed (0 or 1)>\n" RESET, program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *dictionary_path = argv[1];
    int is_hashed = atoi(argv[2]);
    const char *input = argv[3];
    int is_input_hashed = atoi(argv[4]);
    char user_hash[33];

    if (!is_input_hashed) {
        compute_md5(input, "", user_hash);
        printf(BLUE "Generated hash for input '%s': %s\n" RESET, input, user_hash);
    } else {
        strncpy(user_hash, input, 33);
        user_hash[32] = '\0';  // Ensure null-termination
    }

    printf(BLUE "\nProcessing dictionary...\n" RESET);
    if (!process_dictionary(dictionary_path, user_hash, is_hashed)) {
        printf(RED "No match found.\n" RESET);
    }

    return EXIT_SUCCESS;
}
