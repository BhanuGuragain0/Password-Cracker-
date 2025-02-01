#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <time.h>

// Predefined key range for salting the hash
const char *key_range[] = {
    "D76AA478", "E8C7B756", "242070DB", "C1BDCEEE", "F57C0FA", "4787C62A",
    "A8304613", "FD469501", "698098D8", "8B44F7AF", "FFFF5BB1", "895CD7BE",
    "6B901122", "FD987193", "A679438E", "49B40821", "F61E2562", "C040B340",
    "265E5A51", "E9B6C7AA", "D62F105D", "02441453", "D8A1E681", "E7D3FBC8",
    "21E1CDE6", "C33707D6"
};

// Number of keys in the key_range array
const int key_range_size = sizeof(key_range) / sizeof(key_range[0]);

// ANSI color codes for enhanced terminal output
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

// Thread-safe variables
pthread_mutex_t lock;
int found = 0;

// Struct to pass arguments to threads
typedef struct {
    const char *filename;
    const char *user_hash;
    int is_hashed;
    const char *algorithm;
} ThreadArgs;

// Function to calculate hash using the specified algorithm
void compute_hash(const char *input, const char *key, const char *algorithm, char output[65]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, RED "Error: Unable to create EVP_MD_CTX\n" RESET);
        exit(EXIT_FAILURE);
    }

    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md) {
        fprintf(stderr, RED "Error: Unsupported hash algorithm '%s'\n" RESET, algorithm);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
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

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        fprintf(stderr, RED "Error: Digest finalization failed\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    for (unsigned int i = 0; i < hash_len; ++i) {
        snprintf(&output[i * 2], 3, "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';

    EVP_MD_CTX_free(ctx);
}

// Function to check if a line matches the user hash
int check_match(const char *line, const char *user_hash, int is_hashed, const char *algorithm) {
    if (is_hashed) {
        return strcmp(line, user_hash) == 0;
    } else {
        for (int i = 0; i < key_range_size; ++i) {
            char generated_hash[65];
            compute_hash(line, key_range[i], algorithm, generated_hash);

            if (strcmp(generated_hash, user_hash) == 0) {
                printf(GREEN "Match found! Entry: '%s', Key: '%s'\n" RESET, line, key_range[i]);
                return 1;
            }
        }
    }
    return 0;
}

// Thread function to process a portion of the dictionary file
void *process_dictionary_thread(void *args) {
    ThreadArgs *thread_args = (ThreadArgs *)args;
    FILE *file = fopen(thread_args->filename, "r");
    if (!file) {
        perror(RED "Error opening dictionary file" RESET);
        return NULL;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';  // Remove newline character

        pthread_mutex_lock(&lock);
        if (found) {
            pthread_mutex_unlock(&lock);
            break;
        }
        pthread_mutex_unlock(&lock);

        if (check_match(line, thread_args->user_hash, thread_args->is_hashed, thread_args->algorithm)) {
            pthread_mutex_lock(&lock);
            found = 1;
            pthread_mutex_unlock(&lock);
            break;
        }
    }

    fclose(file);
    return NULL;
}

void print_usage(const char *program_name) {
    printf(YELLOW "Usage: %s <dictionary_path> <is_hashed (0 or 1)> <user_input> <is_input_hashed (0 or 1)> <algorithm (md5/sha256)>\n" RESET, program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *dictionary_path = argv[1];
    int is_hashed = atoi(argv[2]);
    const char *input = argv[3];
    int is_input_hashed = atoi(argv[4]);
    const char *algorithm = argv[5];

    // Validate is_hashed and is_input_hashed flags
    if ((is_hashed != 0 && is_hashed != 1) || (is_input_hashed != 0 && is_input_hashed != 1)) {
        fprintf(stderr, RED "Error: is_hashed and is_input_hashed must be 0 or 1.\n" RESET);
        return EXIT_FAILURE;
    }

    // Validate algorithm
    if (strcmp(algorithm, "md5") != 0 && strcmp(algorithm, "sha256") != 0) {
        fprintf(stderr, RED "Error: Unsupported algorithm. Use 'md5' or 'sha256'.\n" RESET);
        return EXIT_FAILURE;
    }

    char user_hash[65];

    if (!is_input_hashed) {
        compute_hash(input, "", algorithm, user_hash);
        printf(BLUE "Generated hash for input '%s': %s\n" RESET, input, user_hash);
    } else {
        strncpy(user_hash, input, 65);
        user_hash[64] = '\0';  // Ensure null-termination
    }

    printf(BLUE "\nProcessing dictionary...\n" RESET);

    // Initialize mutex
    if (pthread_mutex_init(&lock, NULL) != 0) {
        fprintf(stderr, RED "Error: Mutex initialization failed\n" RESET);
        return EXIT_FAILURE;
    }

    // Create threads
    pthread_t threads[4];
    ThreadArgs thread_args = {dictionary_path, user_hash, is_hashed, algorithm};

    for (int i = 0; i < 4; ++i) {
        if (pthread_create(&threads[i], NULL, process_dictionary_thread, &thread_args) != 0) {
            fprintf(stderr, RED "Error: Thread creation failed\n" RESET);
            return EXIT_FAILURE;
        }
    }

    // Wait for threads to finish
    for (int i = 0; i < 4; ++i) {
        pthread_join(threads[i], NULL);
    }

    // Clean up mutex
    pthread_mutex_destroy(&lock);

    if (!found) {
        printf(RED "No match found.\n" RESET);
    }

    return EXIT_SUCCESS;
}
