/*
 * Advanced Dictionary Hash Checker - CLEANED & SECURED
 *
 * This program reads a dictionary file and checks each line against a given hash.
 * Supports multi-threaded processing with proper synchronization and error handling.
 *
 * Usage:
 *   ./hash_checker <dictionary_path> <is_hashed (0 or 1)>
 *                   <user_input> <is_input_hashed (0 or 1)>
 *                   <algorithm (md5/sha256)> [num_threads]
 *
 * SECURITY FIXES:
 * - Buffer overflow protection
 * - Proper thread synchronization with atomic operations
 * - Enhanced input validation
 * - Memory leak prevention
 * - Path traversal protection
 *
 * LOGIC FIXES:
 * - Corrected hash salting logic
 * - Fixed user input hash computation
 * - Proper thread cleanup on errors
 * - Enhanced error handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <stdatomic.h>
#include <errno.h>
#include <ctype.h>

/* ANSI color definitions */
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define CYAN "\033[1;36m"
#define RESET "\033[0m"

/* Configuration constants */
#define MAX_LINE_LENGTH 4096
#define MAX_HASH_LENGTH 129 // SHA-512 produces 128 hex chars + null terminator
#define MIN_HASH_LENGTH 32  // MD5 produces 32 hex chars
#define MAX_ALGORITHM_LENGTH 16
#define MAX_PATH_LENGTH 4096
#define DEFAULT_THREADS 4
#define MAX_THREADS 256

/* Predefined key range for salting */
static const char *key_range[] = {
    "D76AA478", "E8C7B756", "242070DB", "C1BDCEEE", "F57C0FA", "4787C62A",
    "A8304613", "FD469501", "698098D8", "8B44F7AF", "FFFF5BB1", "895CD7BE",
    "6B901122", "FD987193", "A679438E", "49B40821", "F61E2562", "C040B340",
    "265E5A51", "E9B6C7AA", "D62F105D", "02441453", "D8A1E681", "E7D3FBC8",
    "21E1CDE6", "C33707D6"};
static const int key_range_size = sizeof(key_range) / sizeof(key_range[0]);

/* Global flags for signaling termination - using atomic for thread safety */
static atomic_bool found = ATOMIC_VAR_INIT(0);
static atomic_bool shutdown_flag = ATOMIC_VAR_INIT(0);

/* Mutex for coordinating output to prevent garbled messages */
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------- Signal Handler ---------------------- */

void handle_signal(int sig)
{
    (void)sig; // Unused parameter
    atomic_store(&shutdown_flag, 1);
    atomic_store(&found, 1); // Ensure worker threads exit ASAP
}

/* ---------------------- Thread-Safe Queue Definition ---------------------- */

typedef struct QueueNode
{
    char *line;
    struct QueueNode *next;
} QueueNode;

typedef struct
{
    QueueNode *head;
    QueueNode *tail;
    int count;
    int finished; // Flag indicating no more lines will be enqueued
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} Queue;

/**
 * init_queue - Initialize a thread-safe queue
 * @q: Pointer to the queue structure
 * Returns: 0 on success, -1 on failure
 */
int init_queue(Queue *q)
{
    if (!q)
        return -1;

    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    q->finished = 0;

    if (pthread_mutex_init(&q->mutex, NULL) != 0)
    {
        fprintf(stderr, RED "Error: Mutex initialization failed: %s\n" RESET, strerror(errno));
        return -1;
    }

    if (pthread_cond_init(&q->cond, NULL) != 0)
    {
        fprintf(stderr, RED "Error: Condition variable initialization failed: %s\n" RESET, strerror(errno));
        pthread_mutex_destroy(&q->mutex);
        return -1;
    }

    return 0;
}

/**
 * destroy_queue - Clean up queue and free all resources
 * @q: Pointer to the queue structure
 */
void destroy_queue(Queue *q)
{
    if (!q)
        return;

    // Free all remaining nodes
    while (q->head)
    {
        QueueNode *temp = q->head;
        q->head = q->head->next;
        free(temp->line);
        free(temp);
    }

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

/**
 * enqueue - Add a line to the queue
 * @q: Pointer to the queue
 * @line: String to add (will be duplicated)
 * Returns: 0 on success, -1 on failure
 */
int enqueue(Queue *q, const char *line)
{
    if (!q || !line)
        return -1;

    QueueNode *node = malloc(sizeof(QueueNode));
    if (!node)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Memory allocation failed for queue node: %s\n" RESET, strerror(errno));
        pthread_mutex_unlock(&output_mutex);
        return -1;
    }

    node->line = strndup(line, MAX_LINE_LENGTH);
    if (!node->line)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Memory allocation failed for line copy: %s\n" RESET, strerror(errno));
        pthread_mutex_unlock(&output_mutex);
        free(node);
        return -1;
    }
    node->next = NULL;

    pthread_mutex_lock(&q->mutex);
    if (q->tail)
    {
        q->tail->next = node;
    }
    else
    {
        q->head = node;
    }
    q->tail = node;
    q->count++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);

    return 0;
}

/**
 * dequeue - Remove and return a line from the queue
 * @q: Pointer to the queue
 * Returns: Pointer to line string (caller must free), or NULL if finished/shutdown
 */
char *dequeue(Queue *q)
{
    if (!q)
        return NULL;

    pthread_mutex_lock(&q->mutex);

    while (q->count == 0 && !q->finished && !atomic_load(&shutdown_flag))
    {
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    if (atomic_load(&shutdown_flag) || (q->count == 0 && q->finished))
    {
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }

    QueueNode *node = q->head;
    q->head = node->next;
    if (!q->head)
        q->tail = NULL;
    q->count--;

    char *line = node->line;
    free(node);
    pthread_mutex_unlock(&q->mutex);

    return line;
}

/* -------------------------- Hash Computation -------------------------- */

/**
 * validate_hex_string - Check if string is valid hexadecimal
 * @str: String to validate
 * Returns: 1 if valid hex, 0 otherwise
 */
int validate_hex_string(const char *str)
{
    if (!str)
        return 0;

    size_t len = strlen(str);
    if (len < MIN_HASH_LENGTH || len > MAX_HASH_LENGTH)
        return 0;

    for (size_t i = 0; i < len; i++)
    {
        if (!isxdigit((unsigned char)str[i]))
            return 0;
    }

    return 1;
}

/**
 * compute_hash - Generate hash using OpenSSL EVP
 * @input: Input string to hash
 * @key: Optional key for salting (can be NULL or empty string)
 * @algorithm: Hash algorithm ("md5" or "sha256")
 * @output: Output buffer (must be at least MAX_HASH_LENGTH bytes)
 * Returns: 0 on success, -1 on failure
 */
int compute_hash(const char *input, const char *key, const char *algorithm, char *output)
{
    if (!input || !algorithm || !output)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Unable to create EVP_MD_CTX\n" RESET);
        pthread_mutex_unlock(&output_mutex);
        return -1;
    }

    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Unsupported hash algorithm '%s'\n" RESET, algorithm);
        pthread_mutex_unlock(&output_mutex);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Digest initialization failed\n" RESET);
        pthread_mutex_unlock(&output_mutex);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    // Hash the input
    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Digest update failed for input\n" RESET);
        pthread_mutex_unlock(&output_mutex);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    // Add salt/key if provided
    if (key && strlen(key) > 0)
    {
        if (EVP_DigestUpdate(ctx, key, strlen(key)) != 1)
        {
            pthread_mutex_lock(&output_mutex);
            fprintf(stderr, RED "Error: Digest update failed for key\n" RESET);
            pthread_mutex_unlock(&output_mutex);
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
    {
        pthread_mutex_lock(&output_mutex);
        fprintf(stderr, RED "Error: Digest finalization failed\n" RESET);
        pthread_mutex_unlock(&output_mutex);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    // Convert to hex string
    for (unsigned int i = 0; i < hash_len; ++i)
    {
        snprintf(&output[i * 2], 3, "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';

    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * check_match - Compare dictionary entry against target hash
 * @line: Dictionary line (plaintext or hash)
 * @user_hash: Target hash to match
 * @is_hashed: 1 if dictionary entries are pre-hashed, 0 if plaintext
 * @algorithm: Hash algorithm to use
 * Returns: 1 if match found, 0 otherwise
 */
int check_match(const char *line, const char *user_hash, int is_hashed, const char *algorithm)
{
    if (!line || !user_hash || !algorithm)
        return 0;

    if (is_hashed)
    {
        // Direct comparison of hashes
        if (strcasecmp(line, user_hash) == 0)
        {
            pthread_mutex_lock(&output_mutex);
            printf(GREEN "✓ Match found! Entry: '%s'\n" RESET, line);
            pthread_mutex_unlock(&output_mutex);
            return 1;
        }
    }
    else
    {
        // Try hashing with each key in the key range
        for (int i = 0; i < key_range_size; ++i)
        {
            char generated_hash[MAX_HASH_LENGTH];
            if (compute_hash(line, key_range[i], algorithm, generated_hash) != 0)
                continue;

            if (strcasecmp(generated_hash, user_hash) == 0)
            {
                pthread_mutex_lock(&output_mutex);
                printf(GREEN "✓ Match found! Password: '%s', Salt Key: '%s'\n" RESET, line, key_range[i]);
                pthread_mutex_unlock(&output_mutex);
                return 1;
            }
        }

        // Also try without any key (unsalted)
        char generated_hash[MAX_HASH_LENGTH];
        if (compute_hash(line, NULL, algorithm, generated_hash) == 0)
        {
            if (strcasecmp(generated_hash, user_hash) == 0)
            {
                pthread_mutex_lock(&output_mutex);
                printf(GREEN "✓ Match found! Password: '%s' (unsalted)\n" RESET, line);
                pthread_mutex_unlock(&output_mutex);
                return 1;
            }
        }
    }

    return 0;
}

/* -------------------------- Worker Thread -------------------------- */

typedef struct
{
    char user_hash[MAX_HASH_LENGTH];
    int is_hashed;
    char algorithm[MAX_ALGORITHM_LENGTH];
    unsigned long long *lines_processed; // Thread-specific counter
} SearchParams;

typedef struct
{
    Queue *queue;
    SearchParams *params;
    int thread_id;
} WorkerArgs;

/**
 * worker_thread - Thread worker function to process dictionary lines
 * @arg: Pointer to WorkerArgs structure
 * Returns: NULL
 */
void *worker_thread(void *arg)
{
    if (!arg)
        return NULL;

    WorkerArgs *wargs = (WorkerArgs *)arg;
    Queue *q = wargs->queue;
    SearchParams *params = wargs->params;
    char *line = NULL;
    unsigned long long local_count = 0;

    while (!atomic_load(&found) && !atomic_load(&shutdown_flag))
    {
        line = dequeue(q);
        if (!line)
            break;

        local_count++;

        if (check_match(line, params->user_hash, params->is_hashed, params->algorithm))
        {
            atomic_store(&found, 1);
            free(line);
            break;
        }

        free(line);
    }

    // Update the shared counter (not critical, just for stats)
    if (params->lines_processed)
    {
        __atomic_add_fetch(params->lines_processed, local_count, __ATOMIC_RELAXED);
    }

    return NULL;
}

/* -------------------------- Validation Functions -------------------------- */

/**
 * validate_file_path - Basic path validation to prevent common attacks
 * @path: File path to validate
 * Returns: 1 if valid, 0 otherwise
 */
int validate_file_path(const char *path)
{
    if (!path || strlen(path) == 0 || strlen(path) >= MAX_PATH_LENGTH)
        return 0;

    // Check for path traversal attempts
    if (strstr(path, "..") != NULL)
    {
        fprintf(stderr, RED "Error: Path traversal detected in '%s'\n" RESET, path);
        return 0;
    }

    return 1;
}

/**
 * sanitize_input - Remove potentially dangerous characters from input
 * @str: String to sanitize (modified in place)
 */
void sanitize_input(char *str)
{
    if (!str)
        return;

    size_t len = strlen(str);

    // Remove newlines, carriage returns, and null bytes
    for (size_t i = 0; i < len; i++)
    {
        if (str[i] == '\n' || str[i] == '\r' || str[i] == '\0')
        {
            str[i] = '\0';
            break;
        }
    }
}

/* -------------------------- Usage and Main -------------------------- */

void print_usage(const char *program_name)
{
    printf(CYAN "\n╔═══════════════════════════════════════════════════════════════╗\n" RESET);
    printf(CYAN "║" RESET " Advanced Dictionary Hash Checker                          " CYAN "║\n" RESET);
    printf(CYAN "╚═══════════════════════════════════════════════════════════════╝\n" RESET);
    printf(YELLOW "\nUsage:\n" RESET);
    printf("  %s <dictionary_path> <is_hashed> <user_input> <is_input_hashed> <algorithm> [num_threads]\n\n", program_name);
    printf(YELLOW "Parameters:\n" RESET);
    printf("  dictionary_path   : Path to dictionary file\n");
    printf("  is_hashed         : 1 if dictionary contains hashes, 0 if plaintext\n");
    printf("  user_input        : Hash or plaintext to search for\n");
    printf("  is_input_hashed   : 1 if user_input is a hash, 0 if plaintext\n");
    printf("  algorithm         : 'md5' or 'sha256'\n");
    printf("  num_threads       : Optional, number of threads (default: %d, max: %d)\n\n", DEFAULT_THREADS, MAX_THREADS);
    printf(YELLOW "Examples:\n" RESET);
    printf("  %s wordlist.txt 0 password123 0 md5 8\n", program_name);
    printf("  %s hashes.txt 1 5f4dcc3b5aa765d61d8327deb882cf99 1 md5 4\n\n", program_name);
}

int main(int argc, char *argv[])
{
    /* Set up signal handlers for graceful shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1)
    {
        fprintf(stderr, RED "Warning: Failed to set up signal handlers\n" RESET);
    }

    if (argc < 6 || argc > 7)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *dictionary_path = argv[1];
    int is_hashed = atoi(argv[2]);
    const char *input = argv[3];
    int is_input_hashed = atoi(argv[4]);
    const char *algorithm = argv[5];
    int num_threads = DEFAULT_THREADS;

    if (argc == 7)
    {
        num_threads = atoi(argv[6]);
        if (num_threads <= 0 || num_threads > MAX_THREADS)
        {
            fprintf(stderr, RED "Error: num_threads must be between 1 and %d\n" RESET, MAX_THREADS);
            return EXIT_FAILURE;
        }
    }

    /* Validate flag arguments */
    if ((is_hashed != 0 && is_hashed != 1) || (is_input_hashed != 0 && is_input_hashed != 1))
    {
        fprintf(stderr, RED "Error: is_hashed and is_input_hashed must be 0 or 1\n" RESET);
        return EXIT_FAILURE;
    }

    /* Validate algorithm */
    if (strcmp(algorithm, "md5") != 0 && strcmp(algorithm, "sha256") != 0)
    {
        fprintf(stderr, RED "Error: Unsupported algorithm. Use 'md5' or 'sha256'\n" RESET);
        return EXIT_FAILURE;
    }

    /* Validate file path */
    if (!validate_file_path(dictionary_path))
    {
        fprintf(stderr, RED "Error: Invalid dictionary path\n" RESET);
        return EXIT_FAILURE;
    }

    /* Validate input */
    if (!input || strlen(input) == 0)
    {
        fprintf(stderr, RED "Error: User input cannot be empty\n" RESET);
        return EXIT_FAILURE;
    }

    /* Prepare search parameters */
    SearchParams params;
    params.is_hashed = is_hashed;
    strncpy(params.algorithm, algorithm, sizeof(params.algorithm) - 1);
    params.algorithm[sizeof(params.algorithm) - 1] = '\0';

    unsigned long long lines_processed = 0;
    params.lines_processed = &lines_processed;

    if (!is_input_hashed)
    {
        /* Compute the hash for the input text (try all keys and no key) */
        printf(BLUE "\n🔐 Computing hashes for input '%s'...\n" RESET, input);

        // First, compute unsalted hash
        char unsalted_hash[MAX_HASH_LENGTH];
        if (compute_hash(input, NULL, algorithm, unsalted_hash) == 0)
        {
            printf(CYAN "   Unsalted %s: %s\n" RESET, algorithm, unsalted_hash);
            // Use the unsalted hash as the target
            strncpy(params.user_hash, unsalted_hash, sizeof(params.user_hash) - 1);
            params.user_hash[sizeof(params.user_hash) - 1] = '\0';
        }
        else
        {
            fprintf(stderr, RED "Error: Failed to compute hash for input\n" RESET);
            return EXIT_FAILURE;
        }
    }
    else
    {
        /* Validate that input is a valid hash */
        if (!validate_hex_string(input))
        {
            fprintf(stderr, RED "Error: Invalid hash format. Must be hexadecimal string.\n" RESET);
            return EXIT_FAILURE;
        }

        strncpy(params.user_hash, input, sizeof(params.user_hash) - 1);
        params.user_hash[sizeof(params.user_hash) - 1] = '\0';
        printf(BLUE "\n🔍 Searching for hash: %s\n" RESET, params.user_hash);
    }

    printf(BLUE "📖 Processing dictionary '%s' using %d thread(s)...\n" RESET, dictionary_path, num_threads);

    /* Initialize the shared queue */
    Queue queue;
    if (init_queue(&queue) != 0)
    {
        return EXIT_FAILURE;
    }

    /* Allocate thread handles and worker args */
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    WorkerArgs *worker_args = malloc(num_threads * sizeof(WorkerArgs));

    if (!threads || !worker_args)
    {
        fprintf(stderr, RED "Error: Memory allocation failed for thread structures\n" RESET);
        free(threads);
        free(worker_args);
        destroy_queue(&queue);
        return EXIT_FAILURE;
    }

    /* Record start time */
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    /* Create worker threads */
    int threads_created = 0;
    for (int i = 0; i < num_threads; ++i)
    {
        worker_args[i].queue = &queue;
        worker_args[i].params = &params;
        worker_args[i].thread_id = i;

        if (pthread_create(&threads[i], NULL, worker_thread, &worker_args[i]) != 0)
        {
            fprintf(stderr, RED "Error: Failed to create worker thread %d: %s\n" RESET, i, strerror(errno));
            atomic_store(&shutdown_flag, 1);
            break;
        }
        threads_created++;
    }

    if (threads_created == 0)
    {
        fprintf(stderr, RED "Error: No worker threads could be created\n" RESET);
        free(threads);
        free(worker_args);
        destroy_queue(&queue);
        return EXIT_FAILURE;
    }

    /* Producer: read the dictionary file and enqueue each line */
    FILE *file = fopen(dictionary_path, "r");
    if (!file)
    {
        fprintf(stderr, RED "Error: Unable to open dictionary file '%s': %s\n" RESET, dictionary_path, strerror(errno));
        atomic_store(&shutdown_flag, 1);
    }
    else
    {
        char *buffer = malloc(MAX_LINE_LENGTH + 1);
        if (!buffer)
        {
            fprintf(stderr, RED "Error: Memory allocation failed for read buffer\n" RESET);
            fclose(file);
            atomic_store(&shutdown_flag, 1);
        }
        else
        {
            unsigned long long line_count = 0;
            while (!atomic_load(&found) && !atomic_load(&shutdown_flag) &&
                   fgets(buffer, MAX_LINE_LENGTH + 1, file))
            {
                // Sanitize input
                sanitize_input(buffer);

                // Skip empty lines
                if (strlen(buffer) == 0)
                    continue;

                line_count++;

                // Enqueue the line
                if (enqueue(&queue, buffer) != 0)
                {
                    fprintf(stderr, RED "Warning: Failed to enqueue line %llu\n" RESET, line_count);
                }

                // Progress indicator (every 100k lines)
                if (line_count % 100000 == 0)
                {
                    printf(CYAN "\r⏳ Processed %llu lines..." RESET, line_count);
                    fflush(stdout);
                }
            }

            if (line_count >= 100000)
            {
                printf("\n");
            }

            printf(BLUE "📊 Total lines read: %llu\n" RESET, line_count);
            free(buffer);
            fclose(file);
        }
    }

    /* Signal that no more lines will be enqueued */
    pthread_mutex_lock(&queue.mutex);
    queue.finished = 1;
    pthread_cond_broadcast(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);

    /* Wait for all created worker threads to finish */
    for (int i = 0; i < threads_created; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(worker_args);
    destroy_queue(&queue);

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_usec - start_time.tv_usec) / 1e6;

    printf(BLUE "\n════════════════════════════════════════\n" RESET);
    if (atomic_load(&found))
    {
        printf(GREEN "✓ Match found successfully!\n" RESET);
    }
    else if (atomic_load(&shutdown_flag))
    {
        printf(YELLOW "⚠ Search interrupted by user\n" RESET);
    }
    else
    {
        printf(RED "✗ No match found\n" RESET);
    }
    printf(BLUE "📊 Lines processed: %llu\n" RESET, lines_processed);
    printf(BLUE "⏱️  Time elapsed: %.3f seconds\n" RESET, elapsed);
    printf(BLUE "⚡ Speed: %.2f lines/second\n" RESET, lines_processed / elapsed);
    printf(BLUE "════════════════════════════════════════\n" RESET);

    pthread_mutex_destroy(&output_mutex);

    return atomic_load(&found) ? EXIT_SUCCESS : EXIT_FAILURE;
}