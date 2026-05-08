# The Digital Defense Dojo — Application Walkthrough

> **Lead Developer:** C. Rithvik | **Academic Collaborator:** CH. Gayathri  
> **Course:** ECE/Cybersecurity — Data Structures Capstone

---

## Deliverable 2: Application Walkthrough

### 1. System Overview

The Digital Defense Dojo is a simulated cybersecurity network packet analyzer written in C11. It demonstrates four core data structures working in concert to solve real-world network bottleneck problems:

```
Incoming Packets ──→ [Circular Queue] ──→ Analyst Decision ──→ [Doubly Linked List]
                        (Buffer)              │                    (Watchlist)
                                              │
                                        [Quick Sort]  ──→  CSV Export
                                     (Threat Prioritization)

Screen Transitions ──→ [Navigation Stack] (UI History Tracking)
```

---

### 2. How the Networking APIs Interact with the OS

#### 2.1 Theoretical: POSIX Raw Sockets

In a production deployment, the analyzer would use the POSIX `<sys/socket.h>` API:

```c
// 1. Create a raw socket bound to the TCP protocol
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

// 2. Receive raw IP frames from the kernel's network stack
// recvfrom() blocks until a packet arrives on any interface
recvfrom(sockfd, buffer, BUF_SIZE, 0, &src_addr, &addr_len);

// 3. Parse the raw bytes: IP header (20 bytes) + TCP header (20 bytes) + payload
```

**Why raw sockets?** Standard `SOCK_STREAM` (TCP) and `SOCK_DGRAM` (UDP) sockets only deliver application-layer data. `SOCK_RAW` gives access to the full IP frame, including headers — essential for packet inspection.

**Privilege requirement:** Raw sockets require `root` (Linux) or `Administrator` (Windows) because they bypass the kernel's protocol processing, which could be exploited for packet injection.

#### 2.2 Theoretical: libpcap

The alternative is `libpcap`, the industry-standard packet capture library (used by Wireshark and tcpdump):

```c
// 1. Open a capture session on interface "eth0"
pcap_t* handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
//                                        │      │    │
//                                  snap_len  promisc  timeout_ms

// 2. Compile and apply a BPF filter (e.g., capture only TCP port 80)
struct bpf_program fp;
pcap_compile(handle, &fp, "tcp port 80", 0, PCAP_NETMASK_UNKNOWN);
pcap_setfilter(handle, &fp);

// 3. Capture packets in a loop
pcap_loop(handle, -1, packet_handler_callback, NULL);
```

**BPF (Berkeley Packet Filter)** is a kernel-level filtering mechanism that discards irrelevant packets before they reach userspace, dramatically reducing CPU overhead.

#### 2.3 Our Simulation Layer

Since raw packet capture requires root privileges and a live network interface, our application uses a **simulation layer** that generates realistic synthetic packets:

```c
Packet generate_packet(void) {
    Packet pkt;
    pkt.id = g_next_packet_id++;
    generate_random_ip(pkt.src_ip);      // Random IPv4 address
    generate_random_ip(pkt.dst_ip);
    // Random protocol: TCP, UDP, ICMP, HTTP, DNS, SSH, FTP
    // Random threat level: 0-10
    // Realistic payload snippets (SQL injection, SYN floods, etc.)
    return pkt;
}
```

This allows the full data structure pipeline to operate identically to a production system — the only difference is the packet source.

---

### 3. Data Structure 1: Circular Queue (Array-Based)

#### Purpose
Acts as a high-speed ingestion buffer. Incoming packets are enqueued at the `rear` and processed from the `front`.

#### How It Works
The queue uses **modular arithmetic** to wrap indices around a fixed-size array:

```
Initial state:    front=0, rear=0, count=0
                  [_][_][_][_][_][_][_][_]   (capacity = 8)

After 3 enqueues: front=0, rear=3, count=3
                  [P1][P2][P3][_][_][_][_][_]

After 2 dequeues: front=2, rear=3, count=1
                  [_][_][P3][_][_][_][_][_]

After 7 more:     front=2, rear=2, count=8 → FULL
                  [P8][P9][P3][P4][P5][P6][P7][P10]
                       ↑ rear wraps around via (rear+1) % SIZE
```

#### Graceful Overflow
When the buffer is full, `cq_enqueue()` returns `-1` and increments `dropped_count`:
```c
if (cq_is_full(q)) {
    q->dropped_count++;
    // [NETWORK STRAIN] logged in presentation mode
    return -1;  // Packet dropped — no crash, no corruption
}
```

---

### 4. Data Structure 2: Doubly Linked List

#### Purpose
Manages a dynamic watchlist of suspicious IP addresses. The key advantage is **O(1) targeted deletion** — when an IP is cleared, its node is surgically removed by rewiring `prev` and `next` pointers.

#### Deletion Edge Cases
The `wl_remove()` function handles all four cases:

```
Case 1: Only node       Case 2: Head node
[A] → NULL              [A] → [B] → [C]
head = tail = NULL       head = B, B.prev = NULL

Case 3: Tail node       Case 4: Middle node
[A] → [B] → [C]        [A] → [B] → [C]
tail = B, B.next = NULL  A.next = C, C.prev = A
```

After every deletion, the freed pointer is set to `NULL` to prevent dangling references.

---

### 5. Data Structure 3: Stack (Linked-List-Based)

See **Deliverable 3** below for the comprehensive deep-dive.

---

### 6. Quick Sort — Median-of-Three Defensive Design

#### The Problem with Naive Quick Sort
Standard Quick Sort with a fixed pivot (e.g., always picking the last element) degrades to **O(n²)** on sorted or nearly-sorted input. In a packet analyzer, packets often arrive pre-sorted by timestamp — this is a realistic and dangerous worst case.

#### The Solution: Median-of-Three Pivot
Instead of blindly picking the last element, we sample three candidates and pick the **median**:

```
Given subarray[lo..hi], where mid = (lo + hi) / 2:

  Step 1: Examine arr[lo], arr[mid], arr[hi]
  Step 2: Sort these three to find the median
  Step 3: Move the median to arr[hi] (pivot position)
  Step 4: Proceed with standard Lomuto partition

Example: arr = [3, 8, 1, 5, 9, 2, 7]
  Candidates: arr[0]=3, arr[3]=5, arr[6]=7
  Median = 5 → used as pivot
  This avoids the worst case that would occur if we picked 3 (min) or 7 (max)
```

#### Why Descending Sort?
Threats are sorted in **descending** order so the most critical packets appear first. The partition condition is `>=` instead of `<=`:

```c
if (arr[j].threat_level >= pivot) {  // Higher threats go LEFT (first)
    i++;
    swap_packets(&arr[i], &arr[j]);
}
```

---

### 7. Advanced Feature: Dojo Drill Mode

A gamified training exercise that tests all three interactive data structures simultaneously:

1. **Circular Queue**: Packets auto-generate each round, filling the buffer
2. **Doubly Linked List**: Flagged IPs are added to the watchlist
3. **Navigation Stack**: Tracks the Drill → Score → Menu flow

**Scoring Logic:**
| Action | Points | Rationale |
|---|---|---|
| Flag IP with threat ≥ 7 | +100 | Correct identification |
| Flag IP with 4 ≤ threat < 7 | +25 | Cautious but acceptable |
| Flag IP with threat < 4 | −50 | False positive penalty |
| Packet dropped (overflow) | −10 | Failure to process in time |

---

### 8. Advanced Feature: Presentation Memory Mode

When toggled ON, every `malloc` and `free` call prints its raw hexadecimal memory address with a deliberate pause:

```
[MEMORY] malloc(184 bytes) for "SuspiciousIP Node"     → addr: 0x55a3c4e01280  [dojo.c:320]
[MEMORY] free(0x55a3c4e01280)   releasing "SuspiciousIP Node"   [dojo.c:373]
```

This is implemented via wrapper macros that inject `__FILE__` and `__LINE__` at the call site:

```c
#define DOJO_MALLOC(size, label) dojo_malloc((size), (label), __FILE__, __LINE__)
#define DOJO_FREE(ptr, label)   do { dojo_free((ptr), (label), __FILE__, __LINE__); \
                                     (ptr) = NULL; } while(0)
```

The `do { ... } while(0)` pattern ensures the macro is safe in all control-flow contexts (if/else without braces).

---

### 9. Advanced Feature: Chaos Monkey Stress Test

Floods **1,000 packets** into a 256-slot buffer. Expected result:
- ~256 enqueued, ~744 dropped
- All drops logged as `[NETWORK STRAIN]`
- System reports **✓ STABLE** — zero segfaults, zero leaks

This proves the circular queue's bounds checking (modular arithmetic) is bulletproof.

---

### 10. Memory Safety Audit

The application enforces strict memory safety:

| Rule | Implementation |
|---|---|
| Every `malloc` paired with `free` | Global ledger: `g_malloc_count == g_free_count` verified on exit |
| No `strcpy`/`sprintf` | All string ops use `strncpy`/`snprintf` with explicit size limits |
| No buffer overflows | Circular queue uses `% MAX_BUFFER_SIZE`; all arrays bounds-checked |
| No dangling pointers | `DOJO_FREE` macro sets pointer to `NULL` after freeing |
| Graceful failure | `malloc` return checked; stack/queue ops check empty/full states |

---

## Deliverable 3: The Stack Deep-Dive

### Why a Linked-List Stack Instead of an Array Stack?

This is the critical design decision that separates a basic implementation from a systems engineering one.

#### Array-Based Stack: The Limitations

```c
// Array stack — fixed capacity at compile time
#define MAX_STACK_SIZE 64
typedef struct {
    ViewState frames[MAX_STACK_SIZE];
    int top;  // Index of the top element
} ArrayStack;
```

**Problems:**
1. **Wasted memory**: If the user only navigates 3 levels deep, 61 slots (61 × sizeof(ViewState)) sit unused
2. **Overflow risk**: If navigation exceeds 64 levels, the stack overflows — `push` must either crash or silently fail
3. **Fixed at compile time**: The capacity cannot adapt to runtime usage patterns
4. **Contiguous allocation**: The entire array (64 × ~80 bytes = 5,120 bytes) must be allocated as one contiguous block, even if the program never uses most of it

#### Linked-List Stack: The Solution

```c
typedef struct ViewState {
    int              screen_id;
    char             context[MAX_CONTEXT_LEN];
    time_t           entered_at;
    struct ViewState* next;  // Points to the frame below
} ViewState;

typedef struct {
    ViewState* top;   // Pointer to the topmost frame
    int        depth; // Current stack depth
} NavStack;
```

**Advantages:**
1. **Dynamic growth**: Each `push` allocates exactly **one node** (~80 bytes). Memory usage = O(depth)
2. **No overflow**: The stack grows until the system runs out of heap memory (gigabytes)
3. **No waste**: When a frame is popped, its memory is immediately freed back to the OS
4. **Non-contiguous**: Nodes can be scattered across the heap — no need for a large contiguous block

---

### Push: How Memory Pointers Work Under the Hood

```c
void nav_push(NavStack* stack, int screen_id, const char* context) {
    // Step 1: Allocate a new node on the HEAP
    ViewState* node = (ViewState*)DOJO_MALLOC(sizeof(ViewState), "ViewState Node");
    //         ↑                        ↑
    //    local pointer            malloc returns a heap address
    //    (on the stack frame)     e.g., 0x55a3c4e01280

    // Step 2: Fill in the data
    node->screen_id = screen_id;
    strncpy(node->context, context, MAX_CONTEXT_LEN - 1);
    node->entered_at = time(NULL);

    // Step 3: Link the new node to the old top
    node->next = stack->top;
    //          ↑
    //    new node's 'next' pointer now stores the ADDRESS of the old top
    //    e.g., node->next = 0x55a3c4e00f40

    // Step 4: Update the top pointer
    stack->top = node;
    //         ↑
    //    stack->top now stores the ADDRESS of the new node
    //    e.g., stack->top = 0x55a3c4e01280

    stack->depth++;
}
```

#### Visual: Memory State After 3 Pushes

```
stack->top ──→ [ViewState @ 0x...1280]  "Chaos Monkey"
                    │ next
                    ↓
               [ViewState @ 0x...0F40]  "IP Watchlist"
                    │ next
                    ↓
               [ViewState @ 0x...0A00]  "Main Menu"
                    │ next
                    ↓
                  NULL
```

Each node exists at a **different heap address**. The `next` pointer is literally an 8-byte integer holding the memory address of the node below it.

---

### Pop: Freeing Memory and Rewiring Pointers

```c
int nav_pop(NavStack* stack, ViewState* out) {
    if (!stack->top) return -1;  // Guard: empty stack

    // Step 1: Save the top pointer (we'll free it soon)
    ViewState* old_top = stack->top;
    //                    ↑
    //    old_top = 0x55a3c4e01280 (the "Chaos Monkey" node)

    // Step 2: Copy data out before freeing (if caller wants it)
    if (out) {
        out->screen_id = old_top->screen_id;
        strncpy(out->context, old_top->context, MAX_CONTEXT_LEN);
        out->entered_at = old_top->entered_at;
    }

    // Step 3: Move top DOWN to the next node
    stack->top = old_top->next;
    //         ↑
    //    stack->top = 0x55a3c4e00F40 (now points to "IP Watchlist")

    // Step 4: Free the old top's memory
    DOJO_FREE(old_top, "ViewState Node");
    //    free(0x55a3c4e01280) — memory returned to the OS
    //    old_top is set to NULL by the macro (prevents dangling pointer)

    stack->depth--;
    return 0;
}
```

#### Visual: Before and After Pop

```
BEFORE POP:                          AFTER POP:
stack->top → [Chaos Monkey]          stack->top → [IP Watchlist]
                  ↓                                    ↓
             [IP Watchlist]                       [Main Menu]
                  ↓                                    ↓
             [Main Menu]                             NULL
                  ↓
               NULL                  [Chaos Monkey] ← FREED (memory returned)
```

---

### Navigation History Tracking Flow

Here's a complete trace of how the stack tracks a user session:

```
Action                          Stack State (top → bottom)
─────────────────────────────   ──────────────────────────
App starts                      [Main Menu]
User selects "Packet Capture"   [Packet Capture] → [Main Menu]
User returns to menu            [Main Menu]
User selects "Dojo Drill"       [Dojo Drill] → [Main Menu]
Drill completes → Score screen  [Score Screen] → [Dojo Drill] → [Main Menu]
User returns                    [Dojo Drill] → [Main Menu]
User returns                    [Main Menu]
User selects "Nav History"      [Nav History] → [Main Menu]
  → System displays full stack, user sees their navigation path
User returns                    [Main Menu]
User exits                      Stack destroyed (all nodes freed)
```

Each push costs exactly **one `malloc`**. Each pop costs exactly **one `free`**. The memory ledger balances perfectly: `g_malloc_count == g_free_count`.

---

### The Critical Trade-off Table

| Feature | Array Stack | Linked-List Stack (Chosen) |
|---|---|---|
| Memory usage | Fixed (wastes space) | Dynamic (exact fit) |
| Max capacity | Hardcoded limit | Limited only by heap |
| Overflow risk | Yes (crashes or fails) | Virtually none |
| Push complexity | O(1) | O(1) |
| Pop complexity | O(1) | O(1) |
| Cache locality | Better (contiguous) | Worse (scattered) |
| Memory safety demo | Less interesting | **Demonstrates malloc/free lifecycle** |

**Why linked-list wins for this project:** The navigation depth is unpredictable and typically shallow (3-5 levels), but could theoretically go arbitrarily deep. A linked-list stack uses exactly the memory it needs, demonstrates dynamic memory management (which is the course's core objective), and pairs perfectly with the Presentation Mode memory visualization.

---

### Compilation & Execution

```bash
# Compile (Linux/macOS)
gcc -Wall -Wextra -pedantic -std=c11 -o dojo dojo.c

# Compile (Windows with MinGW)
gcc -Wall -Wextra -pedantic -std=c11 -o dojo.exe dojo.c

# Run
./dojo        # Linux
dojo.exe      # Windows

# Memory leak check (Linux)
valgrind --leak-check=full ./dojo
```

---

> *"The mark of a mature systems engineer is not writing code that works — it's writing code that cannot fail."*
