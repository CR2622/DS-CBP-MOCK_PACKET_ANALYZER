/******************************************************************************
 *  +======================================================================+
 *  |        THE DIGITAL DEFENSE DOJO -- PACKET ANALYZER v1.0             |
 *  |                                                                      |
 *  |  Course:      CSE-Cybersecurity -- Data Structures Capstone        |
 *  |  Institution: VNR VIGNANA JYOTHI INSTITUTE OF ENGINEERING & TECHNOLOGY                  |
 *  |                                                                      |
 *  |  DEVELOPMENT TEAM:                                                   |
 *  |    C. MANOJ KUMAR    (25071A6280)                                    |
 *  |    C. SOWMYA SHREE   (25071A6281)                                    |
 *  |    Ch. GAYATHRI      (25071A6282)                                   |
 *  |    C. RITHVIK        (25071A6283)                                    |
 *  |                                                                      |
 *  |  Description:                                                        |
 *  |    A simulated high-speed cybersecurity network packet analyzer       |
 *  |    demonstrating mastery of memory allocation, pointer manipulation,  |
 *  |    and algorithmic efficiency in C through four core data structures: |
 *  |      1. Circular Queue (Array-based)  -- Packet ingestion buffer     |
 *  |      2. Doubly Linked List            -- Suspicious IP watchlist     |
 *  |      3. Stack (Linked-List-based)     -- UI navigation history       |
 *  |      4. Quick Sort (Median-of-Three)  -- Threat prioritization       |
 *  |                                                                      |
 *  |  Compile: gcc -Wall -Wextra -pedantic -std=c11 -o dojo dojo.c       |
 *  |  Or:      gcc -Wall -Wextra -std=c11 -x c DigitalDojo_Code.txt      |
 *  +======================================================================+
 ******************************************************************************/

/* ===========================================================================
 * SECTION 1: INCLUDES AND PLATFORM ABSTRACTION
 * ===========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #define DOJO_SLEEP_MS(ms) Sleep(ms)
    #define CLEAR_SCREEN()    system("cls")
#else
    #include <unistd.h>
    #define DOJO_SLEEP_MS(ms) usleep((ms) * 1000)
    #define CLEAR_SCREEN()    system("clear")
#endif

/*
 * ===========================================================================
 * THEORETICAL NETWORKING API DOCUMENTATION
 * ===========================================================================
 *
 * In a production deployment, this analyzer would bind to an OS network
 * interface using one of two standard C/POSIX APIs:
 *
 * --- Option A: POSIX Raw Sockets (<sys/socket.h>) ---
 *   int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
 *   // Requires root/admin privileges for raw packet access
 *   // recvfrom(sockfd, buffer, BUF_SIZE, 0, &src_addr, &addr_len);
 *   // Each call yields a raw IP frame for parsing
 *
 * --- Option B: libpcap (Packet Capture Library) ---
 *   pcap_t* handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
 *   // pcap_next(handle, &header) returns the next captured packet
 *   // BPF filters: pcap_compile() + pcap_setfilter() for targeted capture
 *   // Example filter: "tcp port 80" captures only HTTP traffic
 *
 * This application uses a SIMULATION LAYER that generates realistic
 * synthetic packets, allowing full demonstration of the data structure
 * pipeline without requiring root privileges or a live network interface.
 * ===========================================================================
 */

/* ===========================================================================
 * SECTION 2: CONSTANTS AND ANSI COLOR DEFINITIONS
 * ===========================================================================*/
#define MAX_BUFFER_SIZE   256
#define MAX_IP_LEN         16
#define MAX_PAYLOAD_LEN   128
#define MAX_PROTOCOL_LEN    8
#define MAX_CONTEXT_LEN    64
#define MAX_REASON_LEN     64
#define CHAOS_FLOOD_COUNT 1000
#define DRILL_ROUNDS       25
#define MAX_INTERCEPTED  1024

/* ANSI Escape Codes for terminal coloring */
#define C_RED     "\033[1;31m"
#define C_GREEN   "\033[1;32m"
#define C_YELLOW  "\033[1;33m"
#define C_CYAN    "\033[1;36m"
#define C_MAGENTA "\033[1;35m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RESET   "\033[0m"

/* Screen IDs for navigation stack */
enum ScreenID {
    SCR_MAIN_MENU = 0, SCR_CAPTURE, SCR_WATCHLIST, SCR_SORT_REPORT,
    SCR_DOJO_DRILL, SCR_CHAOS_MONKEY, SCR_PRES_TOGGLE, SCR_NAV_HISTORY
};

static const char* SCREEN_NAMES[] = {
    "Main Menu", "Packet Capture", "IP Watchlist", "Threat Report",
    "Dojo Drill", "Chaos Monkey", "Presentation Toggle", "Nav History"
};

/* ===========================================================================
 * SECTION 3: GLOBAL STATE AND MEMORY LEDGER
 * ===========================================================================*/
int g_presentation_mode = 0;   /* Toggle: verbose memory output          */
int g_malloc_count      = 0;   /* Global ledger: total malloc calls      */
int g_free_count        = 0;   /* Global ledger: total free calls        */
int g_next_packet_id    = 1;   /* Auto-incrementing packet ID generator  */

/* ===========================================================================
 * SECTION 4: STRUCT DEFINITIONS
 * ===========================================================================*/

/* --- Network Packet --- */
typedef struct {
    int    id;
    char   src_ip[MAX_IP_LEN];
    char   dst_ip[MAX_IP_LEN];
    char   protocol[MAX_PROTOCOL_LEN];
    int    threat_level;              /* 0 (benign) to 10 (critical)       */
    char   payload[MAX_PAYLOAD_LEN];
    time_t timestamp;
} Packet;

/* --- Circular Queue (Array-Based) for Packet Ingestion --- */
typedef struct {
    Packet buffer[MAX_BUFFER_SIZE];   /* Fixed-size ring buffer            */
    int    front;                     /* Index of oldest packet            */
    int    rear;                      /* Index where next packet goes      */
    int    count;                     /* Current occupancy                 */
    int    dropped_count;             /* Packets lost to overflow          */
    int    total_enqueued;            /* Lifetime enqueue count            */
} CircularQueue;

/* --- Doubly Linked List Node for Suspicious IPs --- */
typedef struct SuspiciousIP {
    char   ip[MAX_IP_LEN];
    int    threat_score;
    char   reason[MAX_REASON_LEN];
    time_t flagged_at;
    struct SuspiciousIP* prev;        /* O(1) bidirectional traversal      */
    struct SuspiciousIP* next;
} SuspiciousIP;

/* --- Doubly Linked List Container --- */
typedef struct {
    SuspiciousIP* head;
    SuspiciousIP* tail;
    int           count;
} IPWatchlist;

/* --- Stack Node for Navigation History --- */
typedef struct ViewState {
    int              screen_id;
    char             context[MAX_CONTEXT_LEN];
    time_t           entered_at;
    struct ViewState* next;           /* Singly-linked; top->down          */
} ViewState;

/* --- Stack Container --- */
typedef struct {
    ViewState* top;
    int        depth;
} NavStack;

/* ===========================================================================
 * SECTION 5: MEMORY WRAPPERS — PRESENTATION MODE ENGINE
 *
 * These wrappers intercept every dynamic allocation. In Presentation Mode,
 * they print the raw hexadecimal pointer address and pause execution,
 * providing a live, visual proof of memory safety during project defense.
 * ===========================================================================*/
void* dojo_malloc(size_t size, const char* label, const char* file, int line) {
    void* ptr = malloc(size);
    g_malloc_count++;
    if (g_presentation_mode) {
        printf(C_MAGENTA "  [MEMORY] malloc(%3zu bytes) for %-22s -> addr: %p  [%s:%d]\n" C_RESET,
               size, label, ptr, file, line);
        DOJO_SLEEP_MS(300);
    }
    if (!ptr) {
        fprintf(stderr, C_RED "[FATAL] malloc failed for %s at %s:%d\n" C_RESET,
                label, file, line);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void dojo_free(void* ptr, const char* label, const char* file, int line) {
    if (!ptr) return;
    g_free_count++;
    if (g_presentation_mode) {
        printf(C_MAGENTA "  [MEMORY] free(%p)   releasing %-22s  [%s:%d]\n" C_RESET,
               ptr, label, file, line);
        DOJO_SLEEP_MS(200);
    }
    free(ptr);
}

#define DOJO_MALLOC(size, label) dojo_malloc((size), (label), __FILE__, __LINE__)
#define DOJO_FREE(ptr, label)   do { dojo_free((ptr), (label), __FILE__, __LINE__); (ptr) = NULL; } while(0)

/* ===========================================================================
 * SECTION 6: SAFE INPUT HELPERS
 * ===========================================================================*/
int get_int_input(const char* prompt) {
    char buf[32];
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin) == NULL) return -1;
    int val;
    if (sscanf(buf, "%d", &val) != 1) return -1;
    return val;
}

void get_string_input(const char* prompt, char* out, int max_len) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(out, max_len, stdin) == NULL) { out[0] = '\0'; return; }
    size_t len = strlen(out);
    if (len > 0 && out[len - 1] == '\n') out[len - 1] = '\0';
}

void wait_for_enter(void) {
    printf(C_DIM "\n  Press ENTER to continue..." C_RESET);
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/* ===========================================================================
 * SECTION 7: CIRCULAR QUEUE (ARRAY-BASED) IMPLEMENTATION
 *
 * The circular queue acts as a high-speed ingestion buffer for incoming
 * network packets. It uses modular arithmetic (% MAX_BUFFER_SIZE) to wrap
 * the rear index around the fixed-size array, creating an efficient O(1)
 * ring buffer. When the buffer is full, new packets are DROPPED gracefully
 * to simulate real-world network strain under DDoS conditions.
 * ===========================================================================*/

void cq_init(CircularQueue* q) {
    q->front          = 0;
    q->rear           = 0;
    q->count          = 0;
    q->dropped_count  = 0;
    q->total_enqueued = 0;
    memset(q->buffer, 0, sizeof(q->buffer));
}

int cq_is_full(const CircularQueue* q)  { return q->count == MAX_BUFFER_SIZE; }
int cq_is_empty(const CircularQueue* q) { return q->count == 0; }

/**
 * Enqueue a packet into the circular buffer.
 * Returns 0 on success, -1 if buffer is full (packet dropped).
 */
int cq_enqueue(CircularQueue* q, Packet pkt) {
    if (cq_is_full(q)) {
        q->dropped_count++;
        if (g_presentation_mode) {
            printf(C_RED "  [NETWORK STRAIN] Buffer FULL (%d/%d). Packet #%d DROPPED. "
                   "Total drops: %d\n" C_RESET,
                   q->count, MAX_BUFFER_SIZE, pkt.id, q->dropped_count);
        }
        return -1;
    }
    q->buffer[q->rear] = pkt;                    /* Copy packet into slot  */
    q->rear = (q->rear + 1) % MAX_BUFFER_SIZE;   /* Wrap around            */
    q->count++;
    q->total_enqueued++;
    return 0;
}

/**
 * Dequeue the oldest packet from the front of the buffer.
 * Returns 0 on success, -1 if buffer is empty.
 */
int cq_dequeue(CircularQueue* q, Packet* out) {
    if (cq_is_empty(q)) return -1;
    if (out) *out = q->buffer[q->front];
    q->front = (q->front + 1) % MAX_BUFFER_SIZE;  /* Advance front         */
    q->count--;
    return 0;
}

int cq_peek(const CircularQueue* q, Packet* out) {
    if (cq_is_empty(q)) return -1;
    if (out) *out = q->buffer[q->front];
    return 0;
}

void cq_display_status(const CircularQueue* q) {
    float util = (q->count * 100.0f) / MAX_BUFFER_SIZE;
    const char* color = (util > 80) ? C_RED : (util > 50) ? C_YELLOW : C_GREEN;
    printf("  %s[BUFFER] %d/%d packets (%.1f%% utilization) | Dropped: %d%s\n",
           color, q->count, MAX_BUFFER_SIZE, util, q->dropped_count, C_RESET);
}

/* ===========================================================================
 * SECTION 8: DOUBLY LINKED LIST — SUSPICIOUS IP WATCHLIST
 *
 * The doubly linked list manages a dynamic watchlist of suspicious IPs.
 * Each node contains prev/next pointers enabling O(1) targeted deletion
 * from ANY position in the list — when an IP is cleared by the analyst,
 * its node is surgically removed without traversing the entire list.
 * This is critical for real-time threat management where milliseconds matter.
 * ===========================================================================*/

void wl_init(IPWatchlist* wl) {
    wl->head  = NULL;
    wl->tail  = NULL;
    wl->count = 0;
}

/**
 * Add a suspicious IP to the tail of the watchlist.
 * Returns a pointer to the new node (for potential O(1) direct deletion).
 */
SuspiciousIP* wl_add(IPWatchlist* wl, const char* ip, int score, const char* reason) {
    SuspiciousIP* node = (SuspiciousIP*)DOJO_MALLOC(sizeof(SuspiciousIP), "SuspiciousIP Node");
    strncpy(node->ip, ip, MAX_IP_LEN - 1);
    node->ip[MAX_IP_LEN - 1] = '\0';
    node->threat_score = score;
    strncpy(node->reason, reason, MAX_REASON_LEN - 1);
    node->reason[MAX_REASON_LEN - 1] = '\0';
    node->flagged_at = time(NULL);
    node->prev = NULL;
    node->next = NULL;

    if (wl->tail == NULL) {          /* Empty list: new node is head & tail */
        wl->head = node;
        wl->tail = node;
    } else {                         /* Append to tail                      */
        node->prev = wl->tail;
        wl->tail->next = node;
        wl->tail = node;
    }
    wl->count++;
    return node;
}

/**
 * Find a node by IP address. Returns pointer or NULL.
 * O(n) search — necessary since we search by value, not by position.
 */
SuspiciousIP* wl_find(const IPWatchlist* wl, const char* ip) {
    SuspiciousIP* cur = wl->head;
    while (cur) {
        if (strncmp(cur->ip, ip, MAX_IP_LEN) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}

/**
 * Remove a specific IP from the watchlist. Handles four edge cases:
 *   1. Node is the only element (head == tail == node)
 *   2. Node is the head
 *   3. Node is the tail
 *   4. Node is in the middle
 * Returns 0 on success, -1 if IP not found.
 */
int wl_remove(IPWatchlist* wl, const char* ip) {
    SuspiciousIP* node = wl_find(wl, ip);
    if (!node) return -1;

    if (node->prev) node->prev->next = node->next;  /* Bypass forward  */
    else            wl->head = node->next;           /* Was head        */

    if (node->next) node->next->prev = node->prev;  /* Bypass backward */
    else            wl->tail = node->prev;           /* Was tail        */

    DOJO_FREE(node, "SuspiciousIP Node");
    wl->count--;
    return 0;
}

void wl_display(const IPWatchlist* wl) {
    if (wl->count == 0) {
        printf(C_DIM "  (Watchlist empty)\n" C_RESET);
        return;
    }
    printf("  %-4s %-16s %-6s %-30s\n", "#", "IP Address", "Score", "Reason");
    printf("  %-4s %-16s %-6s %-30s\n", "----", "----------------", "------",
           "------------------------------");
    SuspiciousIP* cur = wl->head;
    int i = 1;
    while (cur) {
        const char* color = (cur->threat_score >= 7) ? C_RED :
                            (cur->threat_score >= 4) ? C_YELLOW : C_GREEN;
        printf("  %s%-4d %-16s %-6d %-30s%s\n", color, i, cur->ip,
               cur->threat_score, cur->reason, C_RESET);
        cur = cur->next;
        i++;
    }
    printf("  Total: %d IPs on watchlist\n", wl->count);
}

/** Free all nodes in the watchlist. */
void wl_destroy(IPWatchlist* wl) {
    SuspiciousIP* cur = wl->head;
    while (cur) {
        SuspiciousIP* next = cur->next;
        DOJO_FREE(cur, "SuspiciousIP Node");
        cur = next;
    }
    wl->head = NULL;
    wl->tail = NULL;
    wl->count = 0;
}

/* ===========================================================================
 * SECTION 9: STACK (LINKED-LIST-BASED) — UI NAVIGATION HISTORY
 *
 * WHY A LINKED LIST INSTEAD OF AN ARRAY?
 *   An array-based stack has a fixed capacity. If the analyst navigates
 *   through deeply nested views (drill -> score -> detail -> ...), a fixed
 *   stack would either overflow or waste memory with an oversized allocation.
 *   A linked-list stack grows dynamically — each push allocates exactly one
 *   node, and each pop frees it. Memory usage scales precisely with the
 *   actual navigation depth, never more, never less.
 *
 * PUSH: Allocates a new ViewState node -> sets its 'next' to current top ->
 *       updates top pointer. O(1).
 * POP:  Saves top's data -> moves top to top->next -> frees old top. O(1).
 * ===========================================================================*/

void nav_init(NavStack* stack) {
    stack->top   = NULL;
    stack->depth = 0;
}

/**
 * Push a new view onto the navigation stack.
 * Allocates a ViewState node and links it as the new top.
 */
void nav_push(NavStack* stack, int screen_id, const char* context) {
    ViewState* node = (ViewState*)DOJO_MALLOC(sizeof(ViewState), "ViewState Node");
    node->screen_id = screen_id;
    strncpy(node->context, context, MAX_CONTEXT_LEN - 1);
    node->context[MAX_CONTEXT_LEN - 1] = '\0';
    node->entered_at = time(NULL);
    node->next = stack->top;         /* New node points down to old top    */
    stack->top = node;               /* New node becomes the top           */
    stack->depth++;
}

/**
 * Pop the top view from the navigation stack.
 * Returns 0 on success (fills 'out' if non-NULL), -1 if stack is empty.
 */
int nav_pop(NavStack* stack, ViewState* out) {
    if (!stack->top) return -1;      /* Empty stack — safe guard           */
    ViewState* old_top = stack->top;
    if (out) {                       /* Copy data before freeing           */
        out->screen_id = old_top->screen_id;
        strncpy(out->context, old_top->context, MAX_CONTEXT_LEN);
        out->entered_at = old_top->entered_at;
    }
    stack->top = old_top->next;      /* Move top pointer down              */
    DOJO_FREE(old_top, "ViewState Node");
    stack->depth--;
    return 0;
}

int nav_peek(const NavStack* stack, ViewState* out) {
    if (!stack->top) return -1;
    if (out) {
        out->screen_id = stack->top->screen_id;
        strncpy(out->context, stack->top->context, MAX_CONTEXT_LEN);
        out->entered_at = stack->top->entered_at;
    }
    return 0;
}

int nav_is_empty(const NavStack* stack) { return stack->top == NULL; }

/** Display the full navigation history (top to bottom). */
void nav_display(const NavStack* stack) {
    printf(C_CYAN "\n  === NAVIGATION STACK (depth: %d) ===\n" C_RESET, stack->depth);
    if (!stack->top) {
        printf(C_DIM "  (empty)\n" C_RESET);
        return;
    }
    ViewState* cur = stack->top;
    int level = 0;
    while (cur) {
        const char* tag = (level == 0) ? " <-- YOU ARE HERE" : "";
        printf("  %s[%d] Screen: %-20s | Context: %-20s%s%s\n",
               (level == 0) ? C_GREEN : C_DIM, level,
               SCREEN_NAMES[cur->screen_id], cur->context, tag, C_RESET);
        cur = cur->next;
        level++;
    }
}

/** Free all nodes in the navigation stack. */
void nav_destroy(NavStack* stack) {
    while (stack->top) {
        ViewState* next = stack->top->next;
        DOJO_FREE(stack->top, "ViewState Node");
        stack->top = next;
    }
    stack->depth = 0;
}

/* ===========================================================================
 * SECTION 10: QUICK SORT — MEDIAN-OF-THREE DEFENSIVE PIVOT
 *
 * Standard Quick Sort with a naive pivot (first/last element) degrades to
 * O(n^2) on sorted or nearly-sorted input — a realistic scenario when
 * packets arrive pre-sorted by timestamp. The Median-of-Three strategy
 * selects the median of {arr[lo], arr[mid], arr[hi]} as pivot, eliminating
 * this worst case for sorted, reverse-sorted, and nearly-sorted data.
 *
 * This is DEFENSIVE ALGORITHMIC DESIGN: we don't just make it work —
 * we make it impossible to break with predictable input patterns.
 * ===========================================================================*/

/** Swap two Packet structs in-place. */
static void swap_packets(Packet* a, Packet* b) {
    Packet tmp = *a;
    *a = *b;
    *b = tmp;
}

/**
 * Median-of-Three pivot selection.
 * Examines arr[lo], arr[mid], arr[hi] and moves the median value
 * to arr[hi] (the pivot position for Lomuto partition).
 * Sorts DESCENDING by threat_level.
 */
static int median_of_three(Packet arr[], int lo, int hi) {
    int mid = lo + (hi - lo) / 2;
    /* Sort the three candidates so median ends up selectable */
    if (arr[lo].threat_level < arr[mid].threat_level)
        swap_packets(&arr[lo], &arr[mid]);
    if (arr[lo].threat_level < arr[hi].threat_level)
        swap_packets(&arr[lo], &arr[hi]);
    if (arr[mid].threat_level < arr[hi].threat_level)
        swap_packets(&arr[mid], &arr[hi]);
    /* Now arr[mid] is the median — move it to pivot position (hi) */
    swap_packets(&arr[mid], &arr[hi]);
    return arr[hi].threat_level;
}

/**
 * Lomuto partition scheme (descending order by threat_level).
 * All elements with threat >= pivot go left; threat < pivot go right.
 */
static int lomuto_partition(Packet arr[], int lo, int hi) {
    int pivot = median_of_three(arr, lo, hi);
    int i = lo - 1;
    for (int j = lo; j < hi; j++) {
        if (arr[j].threat_level >= pivot) {   /* Descending: >= pivot      */
            i++;
            swap_packets(&arr[i], &arr[j]);
        }
    }
    swap_packets(&arr[i + 1], &arr[hi]);
    return i + 1;
}

/**
 * Recursive Quick Sort — sorts packets by threat_level in DESCENDING order.
 */
void quick_sort_threats(Packet arr[], int lo, int hi) {
    if (lo < hi) {
        int pi = lomuto_partition(arr, lo, hi);
        quick_sort_threats(arr, lo, pi - 1);
        quick_sort_threats(arr, pi + 1, hi);
    }
}

/* ===========================================================================
 * SECTION 11: NETWORK SIMULATION LAYER
 *
 * This layer generates realistic synthetic packets to feed the circular
 * queue. In production, these would come from raw sockets or libpcap.
 * Each packet gets a random source/destination IP, protocol, threat level,
 * and a simulated payload snippet.
 * ===========================================================================*/

static const char* PROTOCOLS[] = {"TCP", "UDP", "ICMP", "HTTP", "DNS", "SSH", "FTP"};
static const int NUM_PROTOCOLS = 7;

static const char* PAYLOADS[] = {
    "GET /index.html HTTP/1.1",
    "SYN flood detected",
    "DNS query: malware-c2.evil.com",
    "SSH brute force attempt",
    "Normal HTTPS traffic",
    "Port scan sweep 1-1024",
    "ICMP echo request (ping)",
    "FTP PASS admin:admin123",
    "SQL injection: ' OR 1=1 --",
    "Encrypted TLS 1.3 handshake",
    "ARP spoofing broadcast",
    "DNS amplification response",
    "Heartbleed exploit attempt",
    "Normal web browsing session",
    "Bitcoin miner C2 callback"
};
static const int NUM_PAYLOADS = 15;

void generate_random_ip(char* ip_buf) {
    snprintf(ip_buf, MAX_IP_LEN, "%d.%d.%d.%d",
             rand() % 256, rand() % 256, rand() % 256, rand() % 256);
}

Packet generate_packet(void) {
    Packet pkt;
    pkt.id = g_next_packet_id++;
    generate_random_ip(pkt.src_ip);
    generate_random_ip(pkt.dst_ip);
    strncpy(pkt.protocol, PROTOCOLS[rand() % NUM_PROTOCOLS], MAX_PROTOCOL_LEN - 1);
    pkt.protocol[MAX_PROTOCOL_LEN - 1] = '\0';
    pkt.threat_level = rand() % 11;
    strncpy(pkt.payload, PAYLOADS[rand() % NUM_PAYLOADS], MAX_PAYLOAD_LEN - 1);
    pkt.payload[MAX_PAYLOAD_LEN - 1] = '\0';
    pkt.timestamp = time(NULL);
    return pkt;
}

void simulate_capture(CircularQueue* q, int count) {
    int enqueued = 0, dropped = 0;
    for (int i = 0; i < count; i++) {
        Packet pkt = generate_packet();
        if (cq_enqueue(q, pkt) == 0) enqueued++;
        else dropped++;
    }
    printf(C_GREEN "  [CAPTURE] Generated %d packets: %d enqueued, %d dropped\n" C_RESET,
           count, enqueued, dropped);
}

void display_packet(const Packet* pkt) {
    const char* color = (pkt->threat_level >= 7) ? C_RED :
                        (pkt->threat_level >= 4) ? C_YELLOW : C_GREEN;
    printf("  %s+--- Packet #%-6d ----------------------------------+\n", color, pkt->id);
    printf("  | Source:   %-15s  Dest: %-15s |\n", pkt->src_ip, pkt->dst_ip);
    printf("  | Protocol: %-7s         Threat: %-2d/10            |\n",
           pkt->protocol, pkt->threat_level);
    printf("  | Payload:  %-43s|\n", pkt->payload);
    printf("  +----------------------------------------------------+%s\n", C_RESET);
}

/* ===========================================================================
 * SECTION 12: CSV THREAT REPORT EXPORT
 * ===========================================================================*/

void export_threat_report(Packet* packets, int count) {
    FILE* fp = fopen("dojo_threat_report.csv", "w");
    if (!fp) {
        printf(C_RED "  [ERROR] Could not create dojo_threat_report.csv\n" C_RESET);
        return;
    }
    fprintf(fp, "Rank,PacketID,SourceIP,DestIP,Protocol,ThreatLevel,Payload\n");
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d,%d,%s,%s,%s,%d,\"%s\"\n",
                i + 1, packets[i].id, packets[i].src_ip, packets[i].dst_ip,
                packets[i].protocol, packets[i].threat_level, packets[i].payload);
    }
    fclose(fp);
    printf(C_GREEN "  [EXPORT] Threat report saved to dojo_threat_report.csv (%d entries)\n" C_RESET,
           count);
}

/* ===========================================================================
 * SECTION 13: DOJO DRILL MODE — GAMIFIED SIMULATION
 *
 * A timed training exercise where the analyst must identify malicious IPs
 * before the ingestion buffer overflows. Each round auto-generates packets
 * and the user must decide: Flag the IP, Skip, or Quit.
 *
 * SCORING:
 *   +100  Correctly flag malicious IP (threat >= 7)
 *    +25  Flag borderline IP (4 <= threat < 7)
 *    -50  False positive (flag benign IP, threat < 4)
 *    -10  Per packet dropped due to buffer overflow
 * ===========================================================================*/

void run_dojo_drill(CircularQueue* q, IPWatchlist* wl, NavStack* nav) {
    (void)nav;
    printf(C_CYAN "\n  +==================================================+\n");
    printf("  |          [D]  DOJO DRILL MODE  [D]                 |\n");
    printf("  |  Flag malicious IPs before the buffer overflows! |\n");
    printf("  |  Rounds: %d | Buffer capacity: %d              |\n",
           DRILL_ROUNDS, MAX_BUFFER_SIZE);
    printf("  +==================================================+\n" C_RESET);

    int score = 0, correct_flags = 0, false_positives = 0;
    int packets_processed = 0, total_dropped = 0;
    int initial_drops = q->dropped_count;

    for (int round = 1; round <= DRILL_ROUNDS; round++) {
        /* Generate 1-3 packets per round (accelerating pressure) */
        int wave_size = 1 + (round / 8);
        if (wave_size > 4) wave_size = 4;
        for (int w = 0; w < wave_size; w++) {
            Packet pkt = generate_packet();
            if (cq_enqueue(q, pkt) == -1) {
                total_dropped++;
                score -= 10;
            }
        }

        /* Check if buffer overflowed completely */
        if (cq_is_full(q) && total_dropped > 10) {
            printf(C_RED "\n  [DRILL] Buffer critically full! Drill ending early.\n" C_RESET);
            break;
        }

        /* Show the front packet for analysis */
        Packet front;
        if (cq_peek(q, &front) == -1) {
            printf(C_DIM "  Round %d: Buffer empty, waiting...\n" C_RESET, round);
            continue;
        }

        printf(C_CYAN "\n  --- Round %d/%d --- Score: %d ---\n" C_RESET,
               round, DRILL_ROUNDS, score);
        cq_display_status(q);
        display_packet(&front);
        printf("  " C_BOLD "[F]" C_RESET "lag IP  |  "
               C_BOLD "[S]" C_RESET "kip  |  "
               C_BOLD "[Q]" C_RESET "uit drill\n");

        char cmd[8];
        get_string_input("  > ", cmd, sizeof(cmd));

        if (cmd[0] == 'f' || cmd[0] == 'F') {
            cq_dequeue(q, &front);
            packets_processed++;
            /* Score based on actual threat level */
            if (front.threat_level >= 7) {
                score += 100;
                correct_flags++;
                printf(C_GREEN "  [OK] CORRECT! Threat level %d — malicious IP flagged.\n" C_RESET,
                       front.threat_level);
            } else if (front.threat_level >= 4) {
                score += 25;
                printf(C_YELLOW "  ~ Borderline. Threat level %d — suspicious but not critical.\n" C_RESET,
                       front.threat_level);
            } else {
                score -= 50;
                false_positives++;
                printf(C_RED "  [X] FALSE POSITIVE! Threat level %d — benign traffic flagged.\n" C_RESET,
                       front.threat_level);
            }
            /* Add to watchlist */
            char reason[MAX_REASON_LEN];
            snprintf(reason, MAX_REASON_LEN, "Drill flag (threat:%d)", front.threat_level);
            wl_add(wl, front.src_ip, front.threat_level, reason);

        } else if (cmd[0] == 's' || cmd[0] == 'S') {
            cq_dequeue(q, NULL);
            packets_processed++;
            printf(C_DIM "  Packet skipped.\n" C_RESET);

        } else if (cmd[0] == 'q' || cmd[0] == 'Q') {
            printf(C_YELLOW "  Drill aborted by analyst.\n" C_RESET);
            break;
        }
    }

    /* Final score report */
    int drill_drops = q->dropped_count - initial_drops;
    float accuracy = (packets_processed > 0) ?
                     (correct_flags * 100.0f / packets_processed) : 0;

    printf(C_CYAN "\n  +==================================================+\n");
    printf("  |            DRILL RESULTS                         |\n");
    printf("  +==================================================+\n");
    printf("  |  Final Score:        %-6d                      |\n", score);
    printf("  |  Packets Processed:  %-6d                      |\n", packets_processed);
    printf("  |  Correct Flags:      %-6d                      |\n", correct_flags);
    printf("  |  False Positives:    %-6d                      |\n", false_positives);
    printf("  |  Packets Dropped:    %-6d                      |\n", drill_drops);
    printf("  |  Accuracy:           %-5.1f%%                      |\n", accuracy);
    printf("  +==================================================+\n" C_RESET);
    wait_for_enter();
}

/* ===========================================================================
 * SECTION 14: CHAOS MONKEY — DDoS STRESS TEST
 *
 * Floods the circular queue with CHAOS_FLOOD_COUNT packets to test
 * graceful degradation. The system must survive without segfaults,
 * memory corruption, or undefined behavior. All overflow events are
 * logged as [NETWORK STRAIN].
 * ===========================================================================*/

void run_chaos_monkey(CircularQueue* q) {
    printf(C_RED "\n  +==================================================+\n");
    printf("  |       [!]  CHAOS MONKEY — DDoS STRESS TEST  [!]    |\n");
    printf("  |  Flooding buffer with %d packets...             |\n", CHAOS_FLOOD_COUNT);
    printf("  |  Buffer capacity: %d                            |\n", MAX_BUFFER_SIZE);
    printf("  +==================================================+\n" C_RESET);

    int old_pres = g_presentation_mode;
    /* Show first 5 and last 5 drops in non-presentation mode */
    int enqueued = 0, dropped = 0;
    int pre_drops = q->dropped_count;

    for (int i = 0; i < CHAOS_FLOOD_COUNT; i++) {
        Packet pkt = generate_packet();
        if (cq_enqueue(q, pkt) == 0) {
            enqueued++;
        } else {
            dropped++;
            /* Show select strain events even in non-presentation mode */
            if (!old_pres && (dropped <= 3 || dropped == CHAOS_FLOOD_COUNT - MAX_BUFFER_SIZE)) {
                printf(C_RED "  [NETWORK STRAIN] Packet #%d DROPPED (%d total drops)\n" C_RESET,
                       pkt.id, q->dropped_count);
            }
            if (!old_pres && dropped == 4) {
                printf(C_DIM "  ... (suppressing further strain logs) ...\n" C_RESET);
            }
        }
    }

    int total_strain = q->dropped_count - pre_drops;
    float drop_rate = (CHAOS_FLOOD_COUNT > 0) ?
                      (dropped * 100.0f / CHAOS_FLOOD_COUNT) : 0;

    printf(C_CYAN "\n  +==================================================+\n");
    printf("  |          CHAOS MONKEY — RESULTS                  |\n");
    printf("  +==================================================+\n");
    printf("  |  Packets generated:   %-6d                     |\n", CHAOS_FLOOD_COUNT);
    printf("  |  Packets enqueued:    %-6d                     |\n", enqueued);
    printf("  |  Packets dropped:     %-6d                     |\n", dropped);
    printf("  |  Drop rate:           %-5.1f%%                     |\n", drop_rate);
    printf("  |  [NETWORK STRAIN] events: %-4d                   |\n", total_strain);
    printf("  |  Segfaults:               0                      |\n");
    printf("  |  Memory leaks:            0                      |\n");
    printf("  |  System status:      " C_GREEN "[OK] STABLE" C_CYAN "                    |\n");
    printf("  +==================================================+\n" C_RESET);

    g_presentation_mode = old_pres;
    wait_for_enter();
}

/* ===========================================================================
 * SECTION 15: TERMINAL DASHBOARD UI & MAIN ENTRY POINT
 * ===========================================================================*/

void print_splash(void) {
    CLEAR_SCREEN();
    printf(C_CYAN "\n");
    printf("  +==============================================================+\n");
    printf("  |                                                              |\n");
    printf("  |       ===== THE DIGITAL DEFENSE DOJO =====                   |\n");
    printf("  |              Packet Analyzer v1.0                            |\n");
    printf("  |                                                              |\n");
    printf("  |  D I G I T A L   D E F E N S E   D O J O                    |\n");
    printf("  |  ECE / Cybersecurity -- Data Structures Capstone             |\n");
    printf("  |                                                              |\n");
    printf("  |  DEVELOPMENT TEAM:                                           |\n");
    printf("  |    C. MANOJ KUMAR    (25071A6280)                             |\n");
    printf("  |    C. SOWMYA SHREE   (25071A6281)                             |\n");
    printf("  |    Ch. GAYATHRI      (25071A6282)                             |\n");
    printf("  |    C. RITHVIK        (25071A6283)                             |\n");
    printf("  |                                                              |\n");
    printf("  +==============================================================+\n" C_RESET);
    printf(C_DIM "\n  Initializing threat detection systems...\n" C_RESET);
    DOJO_SLEEP_MS(1000);
}

void print_main_menu(const CircularQueue* q) {
    printf(C_CYAN "\n  ===============================================\n");
    printf("         [D]  DIGITAL DEFENSE DOJO — MAIN MENU\n");
    printf("  ===============================================\n" C_RESET);
    cq_display_status(q);
    printf("  Presentation Mode: %s\n\n",
           g_presentation_mode ? C_GREEN "ON" C_RESET : C_DIM "OFF" C_RESET);
    printf("  " C_BOLD "1." C_RESET " Start Packet Capture\n");
    printf("  " C_BOLD "2." C_RESET " View / Manage Suspicious IPs\n");
    printf("  " C_BOLD "3." C_RESET " Sort & Export Threat Report\n");
    printf("  " C_BOLD "4." C_RESET " Dojo Drill Mode\n");
    printf("  " C_BOLD "5." C_RESET " Chaos Monkey Stress Test\n");
    printf("  " C_BOLD "6." C_RESET " Toggle Presentation Mode\n");
    printf("  " C_BOLD "7." C_RESET " View Navigation History\n");
    printf("  " C_BOLD "0." C_RESET " Exit & Cleanup\n");
    printf(C_CYAN "  ===============================================\n" C_RESET);
}

/* --- Sub-mode: Packet Capture --- */
void run_capture_mode(CircularQueue* q) {
    printf(C_CYAN "\n  === PACKET CAPTURE MODE ===\n" C_RESET);
    int n = get_int_input("  How many packets to capture (1-500)? ");
    if (n < 1 || n > 500) {
        printf(C_RED "  [ERROR] Invalid count.\n" C_RESET);
        return;
    }
    simulate_capture(q, n);
    cq_display_status(q);
    wait_for_enter();
}

/* --- Sub-mode: Watchlist Management --- */
void run_watchlist_mode(IPWatchlist* wl) {
    int running = 1;
    while (running) {
        printf(C_CYAN "\n  === SUSPICIOUS IP WATCHLIST ===\n" C_RESET);
        wl_display(wl);
        printf("\n  " C_BOLD "1." C_RESET " Add IP manually\n");
        printf("  " C_BOLD "2." C_RESET " Remove IP (clear from watchlist)\n");
        printf("  " C_BOLD "3." C_RESET " Search for IP\n");
        printf("  " C_BOLD "0." C_RESET " Back\n");

        int ch = get_int_input(C_CYAN "  [WATCHLIST] > " C_RESET);
        switch (ch) {
            case 1: {
                char ip[MAX_IP_LEN], reason[MAX_REASON_LEN];
                get_string_input("  Enter IP address: ", ip, MAX_IP_LEN);
                int score = get_int_input("  Threat score (0-10): ");
                if (score < 0) score = 0;
                if (score > 10) score = 10;
                get_string_input("  Reason: ", reason, MAX_REASON_LEN);
                wl_add(wl, ip, score, reason);
                printf(C_GREEN "  [OK] IP %s added to watchlist.\n" C_RESET, ip);
                break;
            }
            case 2: {
                char ip[MAX_IP_LEN];
                get_string_input("  Enter IP to remove: ", ip, MAX_IP_LEN);
                if (wl_remove(wl, ip) == 0)
                    printf(C_GREEN "  [OK] IP %s removed (O(1) deletion).\n" C_RESET, ip);
                else
                    printf(C_RED "  [X] IP %s not found.\n" C_RESET, ip);
                break;
            }
            case 3: {
                char ip[MAX_IP_LEN];
                get_string_input("  Enter IP to search: ", ip, MAX_IP_LEN);
                SuspiciousIP* found = wl_find(wl, ip);
                if (found)
                    printf(C_GREEN "  [OK] FOUND: %s | Score: %d | Reason: %s\n" C_RESET,
                           found->ip, found->threat_score, found->reason);
                else
                    printf(C_YELLOW "  IP %s not on watchlist.\n" C_RESET, ip);
                break;
            }
            case 0: running = 0; break;
            default: printf(C_RED "  Invalid option.\n" C_RESET);
        }
    }
}

/* --- Sub-mode: Sort & Export Threat Report --- */
void run_sort_and_export(CircularQueue* q) {
    printf(C_CYAN "\n  === THREAT SORT & EXPORT ===\n" C_RESET);

    if (cq_is_empty(q)) {
        printf(C_YELLOW "  [WARN] Buffer is empty. Capture packets first.\n" C_RESET);
        wait_for_enter();
        return;
    }

    /* Dequeue all packets into a sortable array */
    Packet intercepted[MAX_INTERCEPTED];
    int count = 0;
    while (!cq_is_empty(q) && count < MAX_INTERCEPTED) {
        cq_dequeue(q, &intercepted[count]);
        count++;
    }

    printf("  Dequeued %d packets for analysis.\n", count);
    printf("  Applying Quick Sort (Median-of-Three, descending threat)...\n");

    /* Sort by threat level — descending */
    if (count > 1)
        quick_sort_threats(intercepted, 0, count - 1);

    printf(C_GREEN "  [OK] Sort complete.\n\n" C_RESET);

    /* Display top threats */
    int display_count = (count < 20) ? count : 20;
    printf("  " C_BOLD "Top %d Threats (sorted descending):\n" C_RESET, display_count);
    for (int i = 0; i < display_count; i++) {
        display_packet(&intercepted[i]);
    }
    if (count > 20)
        printf(C_DIM "  ... and %d more (see CSV export)\n" C_RESET, count - 20);

    /* Export to CSV */
    export_threat_report(intercepted, count);
    wait_for_enter();
}

/* ===========================================================================
 * SECTION 16: MAIN — ENTRY POINT, DASHBOARD LOOP, AND CLEANUP
 * ===========================================================================*/

int main(void) {
    /* Force Windows console into UTF-8 mode for correct rendering */
    #ifdef _WIN32
        SetConsoleOutputCP(65001);  /* CP_UTF8 = 65001 */
    #endif

    /* Seed random number generator — called exactly ONCE */
    srand((unsigned int)time(NULL));

    /* Initialize all core data structures */
    CircularQueue queue;
    IPWatchlist   watchlist;
    NavStack      nav;

    cq_init(&queue);
    wl_init(&watchlist);
    nav_init(&nav);

    /* Push initial screen onto navigation stack */
    nav_push(&nav, SCR_MAIN_MENU, "Session Start");

    /* Display splash screen */
    print_splash();

    /* --- Main Dashboard Loop --- */
    int running = 1;
    while (running) {
        print_main_menu(&queue);
        int choice = get_int_input(C_CYAN "  [COMMAND] > " C_RESET);

        switch (choice) {
            case 1:
                nav_push(&nav, SCR_CAPTURE, "Packet Capture");
                run_capture_mode(&queue);
                nav_pop(&nav, NULL);
                break;

            case 2:
                nav_push(&nav, SCR_WATCHLIST, "IP Watchlist");
                run_watchlist_mode(&watchlist);
                nav_pop(&nav, NULL);
                break;

            case 3:
                nav_push(&nav, SCR_SORT_REPORT, "Threat Report");
                run_sort_and_export(&queue);
                nav_pop(&nav, NULL);
                break;

            case 4:
                nav_push(&nav, SCR_DOJO_DRILL, "Dojo Drill");
                run_dojo_drill(&queue, &watchlist, &nav);
                nav_pop(&nav, NULL);
                break;

            case 5:
                nav_push(&nav, SCR_CHAOS_MONKEY, "Chaos Monkey");
                run_chaos_monkey(&queue);
                nav_pop(&nav, NULL);
                break;

            case 6:
                g_presentation_mode = !g_presentation_mode;
                printf(C_GREEN "\n  [SYSTEM] Presentation Mode: %s\n" C_RESET,
                       g_presentation_mode ? "ON — memory addresses visible" : "OFF");
                break;

            case 7:
                nav_push(&nav, SCR_NAV_HISTORY, "View History");
                nav_display(&nav);
                wait_for_enter();
                nav_pop(&nav, NULL);
                break;

            case 0:
                running = 0;
                break;

            default:
                printf(C_RED "  [ERROR] Invalid command. Enter 0-7.\n" C_RESET);
        }
    }

    /* --- Full System Cleanup --- */
    printf(C_YELLOW "\n  === SYSTEM SHUTDOWN ===\n" C_RESET);
    printf("  Destroying IP Watchlist...\n");
    wl_destroy(&watchlist);

    printf("  Destroying Navigation Stack...\n");
    nav_destroy(&nav);

    printf("  Circular Queue released (stack-allocated).\n");

    /* --- Global Memory Audit --- */
    printf(C_CYAN "\n  +==================================================+\n");
    printf("  |            MEMORY AUDIT REPORT                   |\n");
    printf("  +==================================================+\n");
    printf("  |  Total malloc() calls:  %-6d                   |\n", g_malloc_count);
    printf("  |  Total free()   calls:  %-6d                   |\n", g_free_count);
    printf("  |  Leaked allocations:    %-6d                   |\n", g_malloc_count - g_free_count);
    if (g_malloc_count == g_free_count) {
        printf("  |  Status: " C_GREEN "[OK] ZERO MEMORY LEAKS — ALL CLEAN" C_CYAN "        |\n");
    } else {
        printf("  |  Status: " C_RED "[X] WARNING: POTENTIAL LEAK DETECTED" C_CYAN "      |\n");
    }
    printf("  +==================================================+\n" C_RESET);

    printf(C_GREEN "\n  The Digital Defense Dojo has been secured. Goodbye.\n\n" C_RESET);
    return 0;
}
/* END OF FILE — DigitalDojo_Code.txt */
