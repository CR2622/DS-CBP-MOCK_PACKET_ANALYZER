#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define VIP 50
#define REG 150
#define ECO 300

// -------- SEATS --------
int vip[VIP] = {0};
int reg[REG] = {0};
int eco[ECO] = {0};

// -------- QUEUE --------
typedef struct {
    int arr[500];
    int front, rear;
} Queue;

void initQ(Queue *q) {
    q->front = q->rear = -1;
}

void enqueue(Queue *q, int id) {
    if (q->rear == 499) return;
    if (q->front == -1) q->front = 0;
    q->arr[++q->rear] = id;
}

int dequeue(Queue *q) {
    if (q->front == -1 || q->front > q->rear) return -1;
    return q->arr[q->front++];
}

// -------- STACK --------
typedef struct {
    int userId, type, seat;
} Undo;

Undo stack[500];
int top = -1;

void push(Undo u) {
    stack[++top] = u;
}

Undo pop() {
    Undo u = {-1,-1,-1};
    if (top == -1) return u;
    return stack[top--];
}

// -------- LINKED LIST --------
typedef struct Node {
    int userId, type, seat;
    struct Node* next;
} Node;

Node* head = NULL;

void addBooking(int id, int type, int seat) {
    Node* n = (Node*)malloc(sizeof(Node));
    n->userId = id;
    n->type = type;
    n->seat = seat;
    n->next = head;
    head = n;
}

// delete only ONE specific seat
int deleteSpecific(int id, int type, int seat) {
    Node *t = head, *p = NULL;

    while (t) {
        if (t->userId == id && t->type == type && t->seat == seat) {
            if (p) p->next = t->next;
            else head = t->next;
            free(t);
            return 1;
        }
        p = t;
        t = t->next;
    }
    return 0;
}

// -------- QUEUES --------
Queue qVIP, qREG, qECO;

// -------- RANDOM GROUP SEATS --------
int getRandomGroupSeats(int arr[], int size, int count) {
    int attempts = 0;

    while (attempts < 100) {
        int start = rand() % (size - count + 1);

        int found = 1;
        for (int i = 0; i < count; i++) {
            if (arr[start + i] != 0) {
                found = 0;
                break;
            }
        }

        if (found) return start;
        attempts++;
    }

    return -1;
}

// -------- BOOK --------
void book() {
    int id, type, seat = -1, count;

    printf("Enter User ID: ");
    scanf("%d", &id);

    printf("1.VIP 2.Regular 3.Economy: ");
    scanf("%d", &type);

    printf("Enter number of tickets: ");
    scanf("%d", &count);

    if (type == 1) seat = getRandomGroupSeats(vip, VIP, count);
    else if (type == 2) seat = getRandomGroupSeats(reg, REG, count);
    else if (type == 3) seat = getRandomGroupSeats(eco, ECO, count);

    if (seat == -1) {
        printf("No adjacent seats available. Added to waiting list\n");
        if (type == 1) enqueue(&qVIP, id);
        if (type == 2) enqueue(&qREG, id);
        if (type == 3) enqueue(&qECO, id);
        return;
    }

    printf("Seats Booked: ");
    for (int i = 0; i < count; i++) {
        if (type == 1) vip[seat + i] = 1;
        if (type == 2) reg[seat + i] = 1;
        if (type == 3) eco[seat + i] = 1;

        addBooking(id, type, seat + i);
        printf("%d ", seat + i + 1);
    }
    printf("\n");
}

// -------- CANCEL (FIXED) --------
void cancel() {
    int id, type, seat;

    printf("Enter User ID: ");
    scanf("%d", &id);

    printf("Enter Type (1-VIP 2-REG 3-ECO): ");
    scanf("%d", &type);

    printf("Enter Seat Number: ");
    scanf("%d", &seat);

    seat--; // convert to index

    int found = deleteSpecific(id, type, seat);

    if (!found) {
        printf("Booking not found\n");
        return;
    }

    if (type == 1) vip[seat] = 0;
    if (type == 2) reg[seat] = 0;
    if (type == 3) eco[seat] = 0;

    Undo u = {id, type, seat};
    push(u);

    printf("Cancelled Seat %d\n", seat + 1);
}

// -------- UNDO --------
void undo() {
    Undo u = pop();

    if (u.userId == -1) {
        printf("Nothing to undo\n");
        return;
    }

    if (u.type == 1 && vip[u.seat] == 0) vip[u.seat] = 1;
    if (u.type == 2 && reg[u.seat] == 0) reg[u.seat] = 1;
    if (u.type == 3 && eco[u.seat] == 0) eco[u.seat] = 1;

    addBooking(u.userId, u.type, u.seat);
    printf("Undo Done: User %d restored seat %d\n", u.userId, u.seat + 1);
}

// -------- STATS --------
void stats() {
    int v=0,r=0,e=0;

    for(int i=0;i<VIP;i++) if(vip[i]) v++;
    for(int i=0;i<REG;i++) if(reg[i]) r++;
    for(int i=0;i<ECO;i++) if(eco[i]) e++;

    printf("\nVIP: %d/%d\nRegular: %d/%d\nEconomy: %d/%d\n",
           v,VIP,r,REG,e,ECO);

    printf("Revenue: %d\n", v*1000 + r*500 + e*200);
}

// -------- DISPLAY --------
void show() {
    Node* t=head;
    printf("\nBookings:\n");

    while(t) {
        printf("User %d -> Type %d Seat %d\n",
               t->userId, t->type, t->seat + 1);
        t = t->next;
    }
}

// -------- MAIN --------
int main() {
    int ch;

    srand(time(0));

    initQ(&qVIP);
    initQ(&qREG);
    initQ(&qECO);

    while (1) {
        printf("\n1.Book\n2.Cancel\n3.Undo\n4.Stats\n5.Show\n6.Exit\n");
        scanf("%d", &ch);

        switch (ch) {
            case 1: book(); break;
            case 2: cancel(); break;
            case 3: undo(); break;
            case 4: stats(); break;
            case 5: show(); break;
            case 6: exit(0);
            default: printf("Invalid\n");
        }
    }
}
