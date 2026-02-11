/*
 * Advanced Dictionary Hash Checker
 *
 * This program reads a dictionary file and checks each line against a given hash.
 * If the input is not already hashed, it computes the hash for the user’s input.
 * A predefined key range is used for salting when necessary.
 *
 * Usage:
 *   ./hash_checker <dictionary_path> <is_hashed (0 or 1)>
 *                   <user_input> <is_input_hashed (0 or 1)>
 *                   <algorithm (md5/sha256)> [num_threads]
 *
 * ANSI color codes are used to enhance terminal output.
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

/* ANSI color definitions */
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

/* Predefined key range for salting */
const char *key_range[] = {
    "D76AA478", "E8C7B756", "242070DB", "C1BDCEEE", "F57C0FA", "4787C62A",
    "A8304613", "FD469501", "698098D8", "8B44F7AF", "FFFF5BB1", "895CD7BE",
    "6B901122", "FD987193", "A679438E", "49B40821", "F61E2562", "C040B340",
    "265E5A51", "E9B6C7AA", "D62F105D", "02441453", "D8A1E681", "E7D3FBC8",
    "21E1CDE6", "C33707D6"};
const int key_range_size = sizeof(key_range) / sizeof(key_range[0]);

/* Global flags for signaling termination */
volatile int found = 0;
volatile sig_atomic_t shutdown_flag = 0;

/* Signal handler to allow graceful shutdown */
void handle_signal(int sig)
{
    shutdown_flag = 1;
    found = 1; // Ensure worker threads exit as soon as possible
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

void init_queue(Queue *q)
{
    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    q->finished = 0;
    if (pthread_mutex_init(&q->mutex, NULL) != 0)
    {
        fprintf(stderr, RED "Error: Mutex initialization failed\n" RESET);
        exit(EXIT_FAILURE);
    }
    if (pthread_cond_init(&q->cond, NULL) != 0)
    {
        fprintf(stderr, RED "Error: Condition variable initialization failed\n" RESET);
        exit(EXIT_FAILURE);
    }
}

void destroy_queue(Queue *q)
{
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

void enqueue(Queue *q, const char *line)
{
    QueueNode *node = malloc(sizeof(QueueNode));
    if (!node)
    {
        fprintf(stderr, RED "Error: Memory allocation failed for queue node\n" RESET);
        exit(EXIT_FAILURE);
    }
    node->line = strdup(line);
    if (!node->line)
    {
        fprintf(stderr, RED "Error: Memory allocation failed for line copy\n" RESET);
        free(node);
        exit(EXIT_FAILURE);
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
}

char *dequeue(Queue *q)
{
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !q->finished && !shutdown_flag)
    {
        pthread_cond_wait(&q->cond, &q->mutex);
    }
    if (shutdown_flag || (q->count == 0 && q->finished))
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

/*
 * compute_hash
 *
 * Computes the hash of the input string (optionally salted with key)
 * using the specified algorithm ("md5" or "sha256"). The result is stored
 * in the provided output buffer (must be at least 65 characters).
 */
void compute_hash(const char *input, const char *key, const char *algorithm, char output[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, RED "Error: Unable to create EVP_MD_CTX\n" RESET);
        exit(EXIT_FAILURE);
    }

    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md)
    {
        fprintf(stderr, RED "Error: Unsupported hash algorithm '%s'\n" RESET, algorithm);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
    {
        fprintf(stderr, RED "Error: Digest initialization failed\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1)
    {
        fprintf(stderr, RED "Error: Digest update failed for input\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (key && strlen(key) > 0)
    {
        if (EVP_DigestUpdate(ctx, key, strlen(key)) != 1)
        {
            fprintf(stderr, RED "Error: Digest update failed for key\n" RESET);
            EVP_MD_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
    {
        fprintf(stderr, RED "Error: Digest finalization failed\n" RESET);
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    for (unsigned int i = 0; i < hash_len; ++i)
    {
        snprintf(&output[i * 2], 3, "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';
    EVP_MD_CTX_free(ctx);
}

/*
 * check_match
 *
 * Compares the given dictionary line with the user hash. If the dictionary
 * entry is plain text, iterates over the key_range for salting. Returns 1 if
 * a match is found, 0 otherwise.
 */
int check_match(const char *line, const char *user_hash, int is_hashed, const char *algorithm)
{
    if (is_hashed)
    {
        if (strcmp(line, user_hash) == 0)
        {
            printf(GREEN "Match found! Entry: '%s'\n" RESET, line);
            return 1;
        }
    }
    else
    {
        for (int i = 0; i < key_range_size; ++i)
        {
            char generated_hash[65];
            compute_hash(line, key_range[i], algorithm, generated_hash);
            if (strcmp(generated_hash, user_hash) == 0)
            {
                printf(GREEN "Match found! Entry: '%s', Key: '%s'\n" RESET, line, key_range[i]);
                return 1;
            }
        }
    }
    return 0;
}

/* -------------------------- Worker Thread -------------------------- */

/* Structure to hold search parameters */
typedef struct
{
    char user_hash[65];
    int is_hashed;
    char algorithm[16];
} SearchParams;

/* Structure to pass arguments to each worker thread */
typedef struct
{
    Queue *queue;
    SearchParams *params;
} WorkerArgs;

/*
 * worker_thread
 *
 * Worker threads dequeue lines from the shared queue and check for a match.
 * The thread exits when a match is found, if a shutdown is signaled, or when
 * no more lines are available.
 */
void *worker_thread(void *arg)
{
    WorkerArgs *wargs = (WorkerArgs *)arg;
    Queue *q = wargs->queue;
    SearchParams *params = wargs->params;
    char *line = NULL;

    while (!found && !shutdown_flag && (line = dequeue(q)) != NULL)
    {
        if (check_match(line, params->user_hash, params->is_hashed, params->algorithm))
        {
            found = 1;
            free(line);
            break;
        }
        free(line);
    }
    return NULL;
}

/* -------------------------- Usage and Main -------------------------- */

void print_usage(const char *program_name)
{
    printf(YELLOW "Usage: %s <dictionary_path> <is_hashed (0 or 1)> <user_input> <is_input_hashed (0 or 1)> <algorithm (md5/sha256)> [num_threads]\n" RESET, program_name);
}

int main(int argc, char *argv[])
{
    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

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
    int num_threads = 4; // Default thread count
    if (argc == 7)
    {
        num_threads = atoi(argv[6]);
        if (num_threads <= 0)
        {
            fprintf(stderr, RED "Error: num_threads must be a positive integer.\n" RESET);
            return EXIT_FAILURE;
        }
    }

    /* Validate flag arguments */
    if ((is_hashed != 0 && is_hashed != 1) || (is_input_hashed != 0 && is_input_hashed != 1))
    {
        fprintf(stderr, RED "Error: is_hashed and is_input_hashed must be 0 or 1.\n" RESET);
        return EXIT_FAILURE;
    }

    /* Validate algorithm */
    if (strcmp(algorithm, "md5") != 0 && strcmp(algorithm, "sha256") != 0)
    {
        fprintf(stderr, RED "Error: Unsupported algorithm. Use 'md5' or 'sha256'.\n" RESET);
        return EXIT_FAILURE;
    }

    /* Prepare search parameters */
    SearchParams params;
    params.is_hashed = is_hashed;
    strncpy(params.algorithm, algorithm, sizeof(params.algorithm) - 1);
    params.algorithm[sizeof(params.algorithm) - 1] = '\0';

    if (!is_input_hashed)
    {
        /* Compute the hash for the input text */
        compute_hash(input, "", algorithm, params.user_hash);
        printf(BLUE "Generated hash for input '%s': %s\n" RESET, input, params.user_hash);
    }
    else
    {
        strncpy(params.user_hash, input, sizeof(params.user_hash) - 1);
        params.user_hash[sizeof(params.user_hash) - 1] = '\0';
    }

    printf(BLUE "\nProcessing dictionary '%s' using %d thread(s)...\n" RESET, dictionary_path, num_threads);

    /* Initialize the shared queue */
    Queue queue;
    init_queue(&queue);

    /* Prepare worker thread arguments */
    WorkerArgs wargs;
    wargs.queue = &queue;
    wargs.params = &params;

    /* Allocate thread handles dynamically */
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    if (!threads)
    {
        fprintf(stderr, RED "Error: Memory allocation failed for thread handles\n" RESET);
        destroy_queue(&queue);
        return EXIT_FAILURE;
    }

    /* Record start time */
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    /* Create worker threads */
    for (int i = 0; i < num_threads; ++i)
    {
        if (pthread_create(&threads[i], NULL, worker_thread, &wargs) != 0)
        {
            fprintf(stderr, RED "Error: Failed to create worker thread %d\n" RESET, i);
            shutdown_flag = 1;
            break;
        }
    }

    /* Producer: read the dictionary file and enqueue each line */
    FILE *file = fopen(dictionary_path, "r");
    if (!file)
    {
        fprintf(stderr, RED "Error: Unable to open dictionary file '%s'\n" RESET, dictionary_path);
        shutdown_flag = 1;
    }
    else
    {
        char buffer[1024]; // Increased buffer size for safety
        while (!found && !shutdown_flag && fgets(buffer, sizeof(buffer), file))
        {
            // SECURITY FIX: Proper newline removal and length check
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n')
            {
                buffer[len - 1] = '\0';
            }
            // Skip empty lines
            if (strlen(buffer) > 0)
            {
                enqueue(&queue, buffer);
            }
        }
        fclose(file);
    }

    /* Signal that no more lines will be enqueued */
    pthread_mutex_lock(&queue.mutex);
    queue.finished = 1;
    pthread_cond_broadcast(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);

    /* Wait for all worker threads to finish */
    for (int i = 0; i < num_threads; ++i)
    {
        pthread_join(threads[i], NULL);
    }
    free(threads);
    destroy_queue(&queue);

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_usec - start_time.tv_usec) / 1e6;

    if (!found)
    {
        printf(RED "No match found.\n" RESET);
    }
    printf(BLUE "Processing complete in %.3f seconds.\n" RESET, elapsed);

    return EXIT_SUCCESS;
}
