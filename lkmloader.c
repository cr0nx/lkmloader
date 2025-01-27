
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>

// System call numbers for module operations
#define INIT_MODULE 175
#define DELETE_MODULE 176
#define FINIT_MODULE 313

// Define the path to modules information
#define PROC_MODULES "/proc/modules"
#define MAX_LINE_LENGTH 1024

struct MemoryStruct {
    char *memory;
    size_t size;
};

// HTTPS configuration structure
struct HttpsConfig {
    const char* cert_path;
    const char* key_path;
    const char* ca_path;
    int verify_peer;
    int verify_host;
    const char* proxy;
    int insecure;
};

// Structure to store module information
struct ModuleInfo {
    char name[64];
    unsigned long address;
    int size;
    int refcount;
    char status[32];
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
void* download_module(const char* url, size_t* size);
int load_module_http(const char* url);
int load_module_init(const char* path);
int load_module_finit(const char* path);
int unload_module(const char* name);
int unload_module_by_address(const char* addr_str);
static void configure_https(CURL *curl);
char* find_module_name_by_address(unsigned long target_address);

// Global HTTPS configuration
struct HttpsConfig https_config = {
    .cert_path = NULL,
    .key_path = NULL,
    .ca_path = NULL,
    .verify_peer = 0,
    .verify_host = 0,
    .proxy = NULL,
    .insecure = 1
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static void configure_https(CURL *curl) {
    if (https_config.cert_path) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, https_config.cert_path);
    }
    if (https_config.key_path) {
        curl_easy_setopt(curl, CURLOPT_SSLKEY, https_config.key_path);
    }
    if (https_config.ca_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, https_config.ca_path);
    }
   
    if (https_config.insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, https_config.verify_peer);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, https_config.verify_host);
    }
   
    if (https_config.proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, https_config.proxy);
    }
}

void* download_module(const char* url, size_t* size) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk = {0};
    long response_code;
    char error_buffer[CURL_ERROR_SIZE];

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
       
        configure_https(curl);

        #ifdef DEBUG
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        #endif

        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
       
        if (res != CURLE_OK) {
            fprintf(stderr, "Download failed: %s\n", error_buffer);
            free(chunk.memory);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return NULL;
        }
       
        if (response_code != 200) {
            fprintf(stderr, "HTTP error: %ld\n", response_code);
            free(chunk.memory);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return NULL;
        }

        curl_easy_cleanup(curl);
    } else {
        free(chunk.memory);
        curl_global_cleanup();
        return NULL;
    }

    curl_global_cleanup();
    *size = chunk.size;
    return chunk.memory;
}

int load_module_finit(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open module file");
        return -1;
    }

    int ret = syscall(FINIT_MODULE, fd, "", 0);
    if (ret < 0) {
        perror("Failed to load module");
        close(fd);
        return -1;
    }

    close(fd);
    printf("Module loaded successfully: %s\n", path);
    return 0;
}

int load_module_init(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open module file");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("Failed to get file size");
        close(fd);
        return -1;
    }

    void *image = malloc(st.st_size);
    if (!image) {
        perror("Failed to allocate memory");
        close(fd);
        return -1;
    }

    if (read(fd, image, st.st_size) != st.st_size) {
        perror("Failed to read module file");
        free(image);
        close(fd);
        return -1;
    }

    int ret = syscall(INIT_MODULE, image, st.st_size, "");
    if (ret < 0) {
        perror("Failed to load module");
        free(image);
        close(fd);
        return -1;
    }

    free(image);
    close(fd);
    printf("Module loaded successfully: %s\n", path);
    return 0;
}

int load_module_http(const char* url) {
    size_t size;
    void *module_data = download_module(url, &size);
    if (!module_data) {
        fprintf(stderr, "Failed to download module from URL: %s\n", url);
        return -1;
    }

    int ret = syscall(INIT_MODULE, module_data, size, "");
    if (ret < 0) {
        perror("Failed to load module");
        free(module_data);
        return -1;
    }

    free(module_data);
    printf("Module loaded successfully from URL: %s\n", url);
    return 0;
}

char* get_module_name_by_address(unsigned long addr) {
    FILE* fp;
    char line[256];
    char* module_name = NULL;
    unsigned long start_addr;

    fp = fopen("/proc/modules", "r");
    if (!fp) {
        perror("Failed to open /proc/modules");
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        char name[64];
        unsigned long size;
        int refs;
        char state[10];
        unsigned long mem_addr;

        if (sscanf(line, "%s %lu %d %s %*s %lx", name, &size, &refs, state, &mem_addr) == 5) {
            if (mem_addr <= addr && addr < mem_addr + size) {
                module_name = strdup(name);
                break;
            }
        }
    }

    fclose(fp);
    return module_name;
}


int unload_module(const char* name) {
    int ret = syscall(DELETE_MODULE, name, O_NONBLOCK);
    if (ret != 0) {
        fprintf(stderr, "Failed to unload module '%s': %s\n",
                name, strerror(errno));
        return -1;
    }

    printf("Successfully unloaded module: %s\n", name);
    return 0;
}


int unload_module_by_address(const char* addr_str) {
    char* endptr;
    unsigned long addr = strtoul(addr_str, &endptr, 16);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid memory address format: %s\n", addr_str);
        return -1;
    }

    char* module_name = get_module_name_by_address(addr);
    if (!module_name) {
        fprintf(stderr, "No module found at address 0x%lx\n", addr);
        return -1;
    }

    printf("Found module '%s' at address 0x%lx\n", module_name, addr);
    int ret = unload_module(module_name);
    free(module_name);
    return ret;
}

void print_usage(const char* program_name) {
    printf("Usage:\n");
    printf("  Load module (finit_module): %s -l <path_to_module.ko>\n", program_name);
    printf("  Load module (init_module):  %s -i <path_to_module.ko>\n", program_name);
    printf("  Load module from HTTP(S):   %s -h <url> [HTTPS options]\n", program_name);
    printf("  Unload module by name:      %s -u <module_name>\n", program_name);
    printf("  Unload module by address:   %s -a <memory_address>\n", program_name);
    printf("\nHTTPS Options:\n");
    printf("  --cert <path>      Client certificate file path\n");
    printf("  --key <path>       Private key file path\n");
    printf("  --cacert <path>    CA certificate file path\n");
    printf("  --no-verify-peer   Disable peer verification\n");
    printf("  --no-verify-host   Disable host verification\n");
    printf("  --proxy <url>      Use proxy server\n");
    printf("  --insecure         Allow insecure SSL connections\n");
    printf("\nExamples:\n");
    printf("  %s -h https://example.com/module.ko --cert client.crt --key client.key\n", program_name);
    printf("  %s -h https://example.com/module.ko --cacert ca.crt --proxy http://proxy:8080\n", program_name);
    printf("  %s -h https://example.com/module.ko --insecure\n", program_name);
    printf("  %s -a 0xffffffffc0000000\n", program_name);
}

int main(int argc, char** argv) {
    int option_index = 0;
    int c;
   
    static struct option long_options[] = {
        {"cert",           required_argument, 0, 'c'},
        {"key",            required_argument, 0, 'k'},
        {"cacert",         required_argument, 0, 'r'},
        {"no-verify-peer", no_argument,       0, 'p'},
        {"no-verify-host", no_argument,       0, 't'},
        {"proxy",          required_argument, 0, 'x'},
        {"insecure",       no_argument,       0, 's'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "l:i:h:u:a:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                https_config.cert_path = optarg;
                break;
            case 'k':
                https_config.key_path = optarg;
                break;
            case 'r':
                https_config.ca_path = optarg;
                break;
            case 'p':
                https_config.verify_peer = 0;
                break;
            case 't':
                https_config.verify_host = 0;
                break;
            case 'x':
                https_config.proxy = optarg;
                break;
            case 's':
                https_config.insecure = 1;
                break;
            case 'l':
                return load_module_finit(optarg);
            case 'i':
                return load_module_init(optarg);
            case 'h':
                return load_module_http(optarg);
            case 'u':
                return unload_module(optarg);
            case 'a':
                return unload_module_by_address(optarg);
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges\n");
        return 1;
    }

    return 0;
}
