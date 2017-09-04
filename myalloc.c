#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <assert.h>

#include "myalloc.h"

// =============== //
/* Data Structures */
// =============== //

/**
 * This data structure represents a block of memory that may or may not have been allocated at any time
 * Perhaps counterintuitive it doesn't actually need to know where it is.
 * Bit masks are required to get the data from this. The maximum size allocatable is (2 ^ (size_t -1)) -1;
 * This is 8 bytes long hence p - 1 is 8 bytes before this memory address.
 * This holds the size of the block, whether the block to its left is free and whether the block after it is free
 * Blocks are stored at the start of a free region of memory, and further note that size is the size excluding the size
 * required to store the header itself.
 */
typedef struct Block{
    size_t data;
}Block;

/**
 * This data structure forms the basis for a doubly linked list.
 * Should be the of size: 3 * size_t
 */
typedef struct Node{
    Block* loc; //A pointer to the memory location where the memory is
    struct Node* prev;
    struct Node* next;
}Node;

// ========================== //
/* Bit masks needed for later */
// ========================== //

//The least significant bit tells us if it is free or not, due to alignment these will probably be zero anyway.
//This second least significant bit tells us whether the previous block is free or not.
//This insight was noted in Wilson et al, 1995.
//In binary we get 00 ... 0001
#define IS_FREE (size_t)1
//In binary we get 11 ... 1110
#define BLOCK_SIZE (size_t)(~(IS_FREE))
//Has to be this size so each block of memory can hold a Node struct and a Block struct.
//Always allocate a multiple of this MIN_ALLOC value so we can keep the last bits unused.
//Recall these sizes are in BYTES and memory is requested in bits
//Ensure double-word alignment
#define MIN_ALLOC (sizeof(void*)*2*8)
//Are these necessary?
#define METHOD_SUCCESS 1
#define METHOD_FAILURE 0

// ================ //
/* Global variables */
// ================ //

//Free list (Doubly Linked List)
Node* free_list = NULL;

// ========================================= //
/* Internal methods that need to be declared */
// ========================================= //

//Note: Documentation given above method implementations in a Doxygen(/JavaDoc)-esque style.
void merge(Node*);
void merge_nodes(Node*, Node*);
Node* find_node(Block*);
void check_init(int);
Block* check_space(int);
void remove_from_list(Node*);
void check_split(Block*, int);
int correctly_sized(int size);
void add_to_list(Node*);
Node* create_node(Block*);
void add_to_start(Node*);
void* lastBlockAddress();
void mmap_failure();
void check_mmap();
Block* more_memory(int);

// ============================================================== //
/* Interface - these are the given methods from the specification */
// ============================================================== //

void* myalloc(int size){
    //Ensure it is of the correct multiple
    size = correctly_sized(size);
    //Sanity check
    if (size == 0) return NULL;
	//Check to see if we have initialised the mmap memory already, and if not then mmap some memory.
    check_init(size);
    //At this point we have either got a free_list or successfully mmaped us some memory
    //Ensure we have enough space to satisfy the request and get the block
    Block* assigned = check_space(size);
    if (assigned == NULL){
        assigned = more_memory(size);
    }
    //Whilst we are receiving the best fit, it may still be substantially too large.
    check_split(assigned, size);
    //Once we are sure this is the best fit then return the pointer
    return (void*)assigned+ sizeof(Block); //Don't give them the header.
}


void myfree(void *ptr){
	ptr -= sizeof(Block);
    Node* n = create_node(ptr);
    add_to_list(n);
    merge(n);
}

// ============================================ //
/* Internal Methods not part of the header file */
// ============================================ //

/**
 * Prints out the current free list.
 */
void printList(){
    Node* n = free_list;
    if (n==NULL) printf("Empty list!");
    while (n!=NULL){
        printf("Node: %#zx of size: %zu ->\n", n, (n->loc->data)&BLOCK_SIZE);
        n = n->next;
    }
    printf("\n");
}

/**
 * Allocates more memory via mmap. Ensures memory can be allocated and if not it will exit the program.
 * @param size the amount of memory to be allocated
 * @return the block of memory allocated by mmap
 */
Block* more_memory(int size){
    void* addr = (void*)0;
    if (free_list != NULL){
        addr = free_list;
    }
    Block* b = mmap(addr,10*(size+MIN_ALLOC),PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,0, 0);
    check_mmap(b);
    return b;
}
/**
 * Prints an appropriate error message upon failure to mmap and exits the program.
 */
void mmap_failure(){
    /*If this ever does happen I'd imagine we couldn't even print out this message since printf requires memory
    itself */
    printf("An error has occurred mapping memory from which no recovery is possible.\n");
    exit(EXIT_FAILURE);
}

/**
 * Finds the address of the last node in the list
 * @return a pointer to the final node in the list
 */
void* lastBlockAddress(){
    Node* n = free_list;
    while (n->next != NULL){
        n = n->next;
    }
    return n;
}
/**
 * Ensures that we have enough space for both flags and for the header
 * @param size the amount of space requested
 * @return size if correct or the first value that satisfies our invariant
 */
int correctly_sized(int size){
    if (size == 0) return size; //Sanity check
    assert(size % MIN_ALLOC >= 0);
    //whilst not divisible make us divisible.
    size = size + (size % MIN_ALLOC);
    return size;
}

/**
 * Creates a node for a given block struct. Should create this in memory allocated to that block.
 * Requires minimum sizing to be enforced or undefinied behaviour may occurr.
 * By default the left and right nodes will be NULL but the loc property will be updated.
 * Additionally note that the NODE block comes after the BLOCK struct.
 * Does **NOT** add it to the list automatically.
 * @param b the block the node has to be created for
 * @return a pointer to the newly created node or NULL if unsuccessful
 */
Node* create_node(Block* b){
    //Sanity check
    if (b == NULL) return NULL;
    /*Recall void* can be cast to anything, but ensure this cast happens BEFORE the pointer arithmetic
    This also ensures that we are adding 1 for each 1 bit in the sizeof(Block) and node sizeof(Node) for each 1 bit
    in sizeof(Block). Further note that Node itself is stored in the block of memory */
    Node* n = (Node*)(b + sizeof(Block)); //Moves the pointer down 1 word (current size of Block) on 64-bit machine.7
    (*n).loc = b;
    (*n).next = NULL;
    (*n).prev = NULL;

    assert(((size_t)n-(size_t)b) == 8*sizeof(Block)); //should be 64 bits apart on a modern machine
    assert(n->loc == b);
    assert(n->next == NULL);
    assert(n->prev == NULL);

    return n;
}

/**
 * Ensure that the block is not signficantly larger than the requested space, this also means we do not fragment if
 * the remaining space will not be able to be allocated due to its size. Otherwise update the space to be more
 * appropriate for this amount of memory requested.
 * @param b the block that is being suggested as a possible allocation. Will be update to be a more appropriate size.
 * @param size the amount of space requested
 */
void check_split(Block* b, int size){
    size_t b_size = b->data & BLOCK_SIZE;
    //If the remainder could not be allocated then don't bother fragmenting
    //Or if we could not store our Node struct in it
    if (b_size - size <= MIN_ALLOC + sizeof(Node)*8){
        remove_from_list(find_node(b));
        return;
    }
    //Other fragment
    /*The assumption here is that both the mmaped space and size would both succeed correctly_sized in the first attempt
     Recall that the size is the size AFTER the header block. Additionally this new_block can be thoughtof as being
     part of the larger, older block that we are making smaller. Each size must be AFTER its header*/
    Block* new_block = ((void*)b+size+sizeof(Block)); //Stored in block itself & recall rules of pointer arithmetic.
    //Ensure pointer arithmetic happens correctly
    assert((size_t)new_block == (size_t)b + size + sizeof(Block));

    //What we want is for b to be the size requested and new_block to be size b_size - size
    //B comes before new_block in memory
    //Update blocks - b gets resized to service the request
    b->data = size & ~IS_FREE; //Gets flags correctly, is not free but do not change its previous
    //Ensure b has been updated correctly
    assert((b->data & BLOCK_SIZE) == size);
    assert((b->data & IS_FREE) == 0);

    //Update the newly created block
    new_block->data = b_size - size - sizeof(Block); //Recall we need to store the header somewhere, so this is now smaller
    new_block->data |= IS_FREE;

    assert((new_block->data & BLOCK_SIZE) == b_size - size - sizeof(Block));
    assert((new_block->data & IS_FREE) == IS_FREE);
    assert((b-> data & BLOCK_SIZE) + (new_block->data & BLOCK_SIZE) != b_size);

    //Update our lists
    Node* old_node = find_node(b);
    assert(old_node != NULL);
    remove_from_list(old_node);
    //Add new block to our list.
    Node* new_node = create_node(new_block);
    add_to_list(new_node);
}
/**
 * Finds the best fit for this given size. Works in O(n).
 * @param size the size of memory requested
 * @return the most appropriate fitting block or NULL if no such thing exists or is otherwise unable to assign memory.
 */
Block* check_space(int size){
    if (free_list == NULL) return NULL;
    Node* best_fit = NULL;
    Node* n = free_list;
    size_t size_difference = ~0; //assign to maximum possible value
    assert(size_difference > 100); //ensure it is size_t and nothing weird has happened
    while (n != NULL){
        Block* b = n->loc;
        //If size > b_size then this will be negative
        size_t n_size_diff = (b->data&BLOCK_SIZE) - size;
        if (n_size_diff >=0){
            if (n_size_diff <= size_difference){
                size_difference = n_size_diff;
                best_fit = n;
            }
        }
        n = n->next;
    }
    if (best_fit == NULL) return NULL;
    return best_fit->loc;
}
/**
 * Checks to see if our mmap memory has been allocated at all. If not allocate it to hold at least 10 objects of the
 * current size. If that fails then just allocate the size requested as a backup. This will update our free_list variable.
 * @param size of the memory requested
 * @return integers corresponding to METHOD_SUCCESS upon success and METHOD_FAILURE upon failure.
 */
void check_init(int size){
    if (size == 0) mmap_failure();
    if (free_list != NULL){
        return; //We already have initialised some memory
    }
    //Otherwise
    size_t mem_size = 10*(size + sizeof(Block)); //Make additional space for the headers.
    Block* b = mmap(0,mem_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,0, 0);
    b->data = (mem_size)&BLOCK_SIZE;
    check_mmap((void*)b);
    free_list = create_node(b);
}

/**
 * Ensure a mmap syscall was successful
 * @param b
 */
void check_mmap(void* b){
    if (b==MAP_FAILED) mmap_failure();
}


/**
 * Adds a new element to the list.
 * This adds the element to the correct place in linked list tree. They list should be ordered in increasing memory
 * locations, as in higher pointers (further from the source) are further in the list.
 * @param n the node to be added to the list (eg newly freed memory)
 */
void add_to_list(Node* n){
    Node* p_prev = free_list; //previous node -- in case of NULL
    Node* p = free_list;
    //search until end or when we encounter a pointer > n's pointer
    while (p != NULL && (size_t)p < (size_t)n){
        p_prev = p;
        p = p->next;
    }
    //Make p the node before we found the last one
    p = p_prev;
    //special case when free_list == NULL
    if (p == NULL) {
        free_list = n;
        n->next = NULL;
        n->prev = NULL;
    }else if (p == free_list){ //special case adding to the start of the list
        add_to_start(n);
    }else{ //normal case
        Node* tempNext = p->next;
        //Make p point forward to n
        p->next  = n;
        //Make n point to the correct previous and next
        n->prev = p;
        n->next = tempNext;
        //Make the next node point its new previous node
        //special case if tempNext = NULL
        if (tempNext != NULL) {
            tempNext->prev = n;
        }
    }
}

/**
 * Adds a new node to the start of the doubly linked list.
 * @param n the node to be added to the start of the list
 */
void add_to_start(Node* n){
    n->next = free_list;
    n->prev = NULL;
    free_list->prev = n;
    free_list = n;
}

/**
 * Removes a node from the doubly linked list used for free blocks of memory ie invoked when a block is assigned
 * Does nothing if the node does not exist in the free list.
 * @param n The block of memory that has just been allocated (or otherwise has to be removed from the list).
 */
void remove_from_list(Node* n){
    if (n==NULL) return;
    Node* p = free_list;
    while (p != NULL && p!=n){
        p = p->next;
    }
    //Special case
    if (p == NULL) return;
    //Special case when removing from start of list
    if (p == free_list){
        if (free_list->next == NULL){
            free_list = NULL;
        }else{
            free_list = free_list->next;
            free_list->prev = NULL;
        }
    }else{
        p = p->prev;
        //The next node after p is now the node after n
        p->next = n->next;
        //The node before the node after n is now p
        //special case p->next == NULL
        if (p->next != NULL){
            p->next->prev = p;
        }
        //n should be removed from the list and data overwritten since it has been mmaped.
    }

}

//We only need to check one block - the most recently freed.
/**
 * Finds and if appropriate merges any contigious blocks from this block.
 * This checks if the block after and before it free and merges if they are. The idea here is that when a block is freed
 * then this method is invoked to minimise fragmentation.
 * It also ensures that the blocks are actually contigious. This allows for additional mmaped memory to be allocated at
 * a different location in memory and for the program to still function.
 * @param n the node recently freed.
 */
void merge(Node* n){
    if (n == NULL) return;
    if (((n->loc->data) & IS_FREE) != IS_FREE) return;
    //We only need to check in the linked list for this.
    //Ensure pointers make sense - for the one after
    Node* after_n = n->next;
    if (after_n != NULL){
        if (after_n == n + (n->loc->data&BLOCK_SIZE)+ sizeof(Block) && (after_n->loc->data&IS_FREE) == IS_FREE){
            merge_nodes(n, after_n);
        }
    }

    //For the one before n
    Node* before_n = n->prev;
    if (before_n != NULL){
        if (before_n + (before_n->loc->data&BLOCK_SIZE) + sizeof(Block) == n  && (before_n->loc->data&IS_FREE) == IS_FREE){
            merge_nodes(before_n, n);
        }
    }

}
/**
 * Merges two contigious blocks into the same block, and updates the list as necessary.
 * Both should be marked as free, and so will the new block.
 * @param a the node the block has to be merged into
 * @param b the node to merge into the node (addressed after a)
 */
void merge_nodes(Node* a, Node* b){
    size_t size = (a->loc->data&BLOCK_SIZE) + (b->loc->data&BLOCK_SIZE) + sizeof(Block); //Recall we are removing 1x header
    a->loc->data = size; //Should not affect the flags
    a->loc->data |= IS_FREE; //mark it as free
    remove_from_list(a);
    remove_from_list(b);
    add_to_list(a);
}

/**
 * Will return the node affiliated with this block of memory.
 * @param b the block of memory to be found in this list
 * @return the node in the binary tree affiliated with this block or NULL if it does not occurr in the binary tree.
 */
Node* find_node(Block* b){
    Node* current = free_list;
    while (current != NULL && current->loc != b){
        current = current->next;
    }
    return current;
}
