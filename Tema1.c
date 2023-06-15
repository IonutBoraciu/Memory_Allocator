//Boraciu Ionut-Sorin 315CA
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);				        \
		}							\
	} while (0)

typedef struct {
	void *head;
	unsigned int data_size;
	unsigned int size;
} list_t;

typedef struct blocks {
	unsigned long start_address;
	size_t size;
	void *miniblock_list;
	struct blocks *next, *prev;
	int no_read;
} block_t;

typedef struct miniblocks {
	unsigned long start_address;
	size_t size;
	unsigned long perm;
	void *rw_buffer;
	int size_buffer;
	struct miniblocks *next, *prev;
} miniblock_t;

typedef struct {
	unsigned long arena_size;
	list_t *alloc_list;
	unsigned long free_mem;
	size_t number_miniblocks;
} arena_t;
list_t *alloc_list(unsigned int data_size)
{
	list_t *list;
	list = malloc(sizeof(list_t));
	DIE(!list, "double list malloc failed");
	list->data_size = data_size;
	list->head = NULL;
	list->size = 0;
	return list;
}

arena_t *alloc_arena(const long size)
{
	arena_t *arena;
	arena = malloc(sizeof(arena_t));
	DIE(!arena, "arena malloc failed");
	arena->arena_size = size;
	arena->alloc_list = alloc_list(sizeof(block_t));
	arena->free_mem = size;
	arena->number_miniblocks = 0;
	return arena;
}

void dealloc_arena(arena_t *arena)
{
	//eliberez fiecare rw_buffer si miniblock, apoi eliberez block-ul
	//si in final eliberez lista arenei si arena in sine
	block_t *block = arena->alloc_list->head;
	while (block) {
		list_t *miniblock_list = (list_t *)block->miniblock_list;
		miniblock_t *miniblock = (miniblock_t *)miniblock_list->head;
		while (miniblock) {
			miniblock_t *next_miniblock = miniblock->next;
			if (miniblock->rw_buffer)
				free(miniblock->rw_buffer);
			free(miniblock);
			miniblock = next_miniblock;
		}
		free(miniblock_list);
		block_t *next_block = block->next;
		free(block);
		block = next_block;
	}
	free(arena->alloc_list);
	free(arena);
}

void mini_right(arena_t *arena, block_t *curr, int adr, int dim, block_t *block)
{
	//daca doresc sa adaug o adresa in continuarea uneia deja existente
	//o voi adauga ca miniblock la block-ul deja existent si voi
	//actualiza dimensiunea block-ului
	miniblock_t *mini;
	mini = malloc(sizeof(miniblock_t));
	DIE(!mini, "mini failed malloc");
	mini->rw_buffer = NULL;
	mini->next = NULL;
	mini->size = dim;
	mini->rw_buffer = NULL;
	mini->perm = 3;
	block->no_read = 0;
	mini->start_address = adr;
	miniblock_t *next2, *prev2;
	list_t *list;
	list = curr->miniblock_list;
	next2 = list->head;
	prev2 = NULL;
	while (next2) {
		prev2 = next2;
		next2 = next2->next;
	}
	prev2->next = mini;
	mini->prev = prev2;
	arena->number_miniblocks++;
	curr->size = curr->size + dim;
}

void check_if_near_miniblock(arena_t *arena, int stop)
{
	//verific daca exista adrese continue care ar trebuii concatenate
	//in urma executarii functiilor mini_right si mini_left care au
	//adaugat un miniblock astfel actualizand dimensiunea block-ului
	block_t *node2;
	node2 = arena->alloc_list->head;
	while (node2 && node2->next && !stop) {
		block_t *node3 = node2->next;
		unsigned long x = node2->size + node2->start_address;
		if (x == node3->start_address) {
			node2->size = node2->size + node3->size;
			miniblock_t *next, *prev;
			list_t *list;
			list = node2->miniblock_list;
			next = list->head;
			prev = NULL;
			while (next) {
				prev = next;
				next = next->next;
			}
			list = node3->miniblock_list;
			prev->next = list->head;
			miniblock_t *next2;
			next2 = list->head;
			next2->prev = prev;
			block_t *node4;
			node4 = node3->next;
			//eliberez block-ul dupa ce am concatenat lista lui de miniblock-uri
			if (!node4) {
				list_t *for_free = node3->miniblock_list;
				if (for_free)
					free(for_free);
				node2->next = NULL;
				free(node3);
				arena->alloc_list->size--;
			} else {
				node2->next = node4;
				node4->prev = node2;
				list_t *for_free;
				for_free = node3->miniblock_list;
				if(for_free!=NULL)
				free(for_free);
				free(node3);
				arena->alloc_list->size--;
			}
		}
		if (node2)
			node2 = node2->next;
	}
}

void mini_left(arena_t *arena, block_t *curr, int adr, int dim, block_t *block)
{
	//verific daca adresa la care vreau sa adaug se continua in alt block
	//si actualizez dimensiunea block-ului in caz afirmativ
	curr->start_address = adr;
	curr->size = curr->size + dim;
	list_t *list = curr->miniblock_list;
	miniblock_t *new_node = malloc(sizeof(miniblock_t));
	DIE(!new_node, "new_node failed malloc");
	new_node->perm = 3;
	block->no_read = 0;
	miniblock_t *old_nodes = list->head;
	old_nodes->prev = new_node;
	new_node->next = old_nodes;
	new_node->prev = NULL;
	new_node->rw_buffer = NULL;
	new_node->size = dim;
	new_node->start_address = adr;
	list->head = new_node;
	arena->number_miniblocks++;
}

void alloc_first(arena_t *arena, block_t *block, miniblock_t *cur, list_t *mini)
{
	//adauga in arena primul block de memorie.
	cur->next = NULL;
	cur->prev = NULL;
	cur->rw_buffer = NULL;
	cur->perm = 3;
	block->no_read = 0;
	mini->head = cur;
	arena->number_miniblocks++;
	block->next = NULL;
	arena->alloc_list->head = block;
	arena->alloc_list->size++;
}

void alloc_order(arena_t *arena, block_t *block, int size, int address)
{
	//adauga un nou block in ordine pentru a se minte continuitatea
	//memoriei virtuale
	block->miniblock_list = alloc_list(sizeof(miniblock_t));
	list_t *miniblock;
	miniblock = block->miniblock_list;
	miniblock_t *node;
	node = malloc(sizeof(miniblock_t));
	DIE(!node, "node malloc failed");
	node->size = size;
	node->rw_buffer = NULL;
	node->perm = 3;
	block->no_read = 0;
	node->start_address = address;
	block_t *curr;
	curr = arena->alloc_list->head;
	block_t *prev = NULL;
	while (curr && address > curr->start_address) {
		prev = curr;
		curr = curr->next;
	}
	block->prev = prev;
	block->next = curr;
	if (prev)
		prev->next = block;
	else
		arena->alloc_list->head = block;
	if (curr)
		curr->prev = block;
	miniblock->head = node;
	arena->number_miniblocks++;
	arena->alloc_list->size++;
}

void alloc_block(arena_t *arena, unsigned long address, unsigned long size)
{
	unsigned long x = address + size;
	if (address >= arena->arena_size) {
		printf("The allocated address is outside the size of arena\n");
	} else if (address < arena->arena_size && x > arena->arena_size) {
		printf("The end address is past the size of the arena\n");
	} else {
		block_t *block = malloc(sizeof(block_t));
		DIE(!block, "block malloc failed");
		arena->free_mem = arena->free_mem - size;
		block->start_address = address;
		block->size = size;

		block_t *curr, *prev;
		curr = arena->alloc_list->head;
		prev = NULL;
		int ok = 1;
		int stop = 0;
		while (curr && !stop && ok) {
			prev = curr;
			if ((curr->size + curr->start_address) == address) {
				ok = 0;
				mini_right(arena, curr, address, size, block);
			} else if ((address + size) == curr->start_address) {
				ok = 0;
				mini_left(arena, curr, address, size, block);
			} else if (address < (curr->start_address + curr->size) &&
				(address + size) > curr->start_address) {
				printf("This zone was already allocated.\n");
				arena->free_mem = arena->free_mem + size;
				stop = 1;
			}
			curr = curr->next;
		}
		if (ok == 1 && !stop) {
			if (arena->number_miniblocks == 0) {
				printf("AICI\n");
				block->miniblock_list = alloc_list(sizeof(miniblock_t));
				list_t *miniblock;
				miniblock = block->miniblock_list;
				miniblock_t *node;
				node = malloc(sizeof(miniblock_t));
				DIE(!node, "node malloc failed");
				node->size = size;
				node->start_address = address;
				alloc_first(arena, block, node, miniblock);
				

			} else {
				//alloc_order(arena, block, size, address);
				printf("AICI\n");
				block->miniblock_list = alloc_list(sizeof(miniblock_t));
	list_t *miniblock;
	miniblock = block->miniblock_list;
	miniblock_t *node;
	node = malloc(sizeof(miniblock_t));
	DIE(!node, "node malloc failed");
	node->size = size;
	node->rw_buffer = NULL;
	node->perm = 3;
	block->no_read = 0;
	node->start_address = address;
	block_t *curr;
	curr = arena->alloc_list->head;
	block_t *prev = NULL;
	while (curr && address > curr->start_address) {
		prev = curr;
		curr = curr->next;
	}
	block->prev = prev;
	block->next = curr;
	if (prev)
		prev->next = block;
	else
		arena->alloc_list->head = block;
	if (curr)
		curr->prev = block;
	miniblock->head = node;
	arena->number_miniblocks++;
	arena->alloc_list->size++;
			}
		}
		if (!stop)
			check_if_near_miniblock(arena, stop);
		if (!ok)
			free(block);
	}
}

void free_first(arena_t *arena, block_t *node, block_t *prev, list_t *list)
{
	miniblock_t *mini;
	mini = list->head;
	if (prev) {
		prev->next = node->next;
		if (node->next)
			node->next->prev = prev;
	} else {
		arena->alloc_list->head = node->next;
		if (node->next)
			node->next->prev = NULL;
	}
	arena->free_mem = arena->free_mem + mini->size;
	if (mini->rw_buffer)
		free(mini->rw_buffer);
	free(mini);
	free(list);
	free(node);
	arena->number_miniblocks--;
	arena->alloc_list->size--;
}

void free_start(arena_t *arena, miniblock_t *mini, block_t *node, list_t *list)
{
	//elibereaza primul miniblock din lista
	miniblock_t *mini_next = mini->next;
	mini_next->prev = NULL;
	list->head = mini_next;
	arena->number_miniblocks--;
	arena->free_mem = arena->free_mem + mini->size;
	node->start_address = mini_next->start_address;
	if (mini->rw_buffer)
		free(mini->rw_buffer);
	free(mini);
}

void free_last(arena_t *arena, miniblock_t *mini, block_t *node)
{
	//elibereaza ultimul miniblock din lista
	mini->prev->next = NULL;
	node->size = node->size - mini->size;
	arena->free_mem = arena->free_mem + mini->size;
	if (mini->rw_buffer)
		free(mini->rw_buffer);
	free(mini);
	arena->number_miniblocks--;
}

void free_middle(miniblock_t *mini, list_t *list, block_t *node, int size)
{
	//elibereaza un miniblock din mijloc caz in care lista de miniblock-uri
	//trebuie sparta in doua block-uri care sa contina bucatile taiete
	//din lista de miniblock-uri
	block_t *n_b = malloc(sizeof(block_t));
	DIE(!n_b, "n_b malloc failed");
	n_b->miniblock_list = alloc_list(sizeof(miniblock_t));
	list_t *new_list = n_b->miniblock_list;
	size_t s = sizeof(miniblock_t);
	miniblock_t *next = mini->next;
	next->prev = NULL;
	new_list->head = next;
	block_t *next1 = node->next;
	n_b->prev = node;
	node->next = n_b;
	if (next1) {
		next1->prev = n_b;
		n_b->next = next1;
	} else {
		n_b->next = NULL;
	}
	miniblock_t *prev = mini->prev;
	prev->next = NULL;
	n_b->start_address = next->start_address;
	miniblock_t *for_size = list->head;
	n_b->size = node->size - size;
	size = size - mini->size;
	node->size = size;
	if (mini->rw_buffer)
		free(mini->rw_buffer);
	free(mini);
}

void free_block(arena_t *arena)
{
	unsigned long address;
	scanf("%lu", &address);
	if (arena->number_miniblocks == 0) {
		printf("Invalid address for free.\n");
		return;
	}
	block_t *prev;
	block_t *node = arena->alloc_list->head;
	block_t *node_next = node->next;
	prev = NULL;
	int stop = 0;
	while (node && !stop) {
		if (address >= node->start_address &&
			address <= (node->start_address + node->size)) {
			list_t *list;
			list = node->miniblock_list;
			miniblock_t *mini;
			mini = list->head;
			if (!mini->next && !mini->prev &&
				mini->start_address == address) {
				free_first(arena, node, prev, list);
				stop = 1;
			} else {
				int size = 0;
				while (mini && !stop) {
					size = size + mini->size;
					if (mini->start_address == address && !mini->prev) {
						free_start(arena, mini, node, list);
						node->size -= size;
						stop = 1;
					} else if (!mini->next && mini->start_address == address) {
						free_last(arena, mini, node);
						stop = 1;
					} else if (mini->start_address == address) {
						stop = 1;
						arena->free_mem = arena->free_mem + mini->size;
						free_middle(mini, list, node, size);
						arena->number_miniblocks--;
						arena->alloc_list->size++;
					}
					if (!stop)
						mini = mini->next;
				}
			}
		}
		if (!stop) {
			prev = node;
			node = node->next;
		}
	}
	if (stop == 0)
		printf("Invalid address for free.\n");
}

void print_char(miniblock_t *mini, block_t *node, int address, int size)
{
	static int started_write = 1 - 1;
	if (mini->rw_buffer && !node->no_read) {
		unsigned long total_mem = mini->size + mini->size_buffer;
		if (address + size <= total_mem && !started_write) {
			unsigned long start_addr = address - mini->start_address;
			for (int i = start_addr; i < mini->size_buffer; i++)
				printf("%c", ((char *)mini->rw_buffer)[i]);
		} else {
			for (int i = 0; i < mini->size_buffer; i++)
				printf("%c", ((char *)mini->rw_buffer)[i]);
			started_write = 1;
		}
	}
}

void read(arena_t *arena, uint64_t address, uint64_t size)
{
	int check = 0;
	int reset = 0;
	block_t *node = arena->alloc_list->head;
	while (node) {
		list_t *list = node->miniblock_list;
		miniblock_t *mini = list->head;
		if (address >= node->start_address &&
			address <= node->start_address + node->size) {
			if (address + size > node->start_address + node->size) {
				printf("Warning: size was bigger than the block size. "
				"Reading %ld characters.\n", node->size);
				size = node->size;
			}
			while (mini) {
				if (mini->perm % 2 == 1) {
					print_char(mini, node, address, size);
					check++;
				} else {
					printf("Invalid permissions for read.");
					check++;
				}
				mini = mini->next;
			}
			printf("\n");
		}
		node = node->next;
	}
	if (check == 0)
		printf("Invalid address for read.\n");
}

int MIN(int a, int b)
{
	if (a < b)
		return a;
	else
		return b;
}

void w_mini(miniblock_t *mini, int *rem_size, int *w_size, int addr, char *data)
{
	//w_size == dimensiunea deja scrisa
	while (mini && *rem_size > 0) {
		unsigned long x = mini->start_address + mini->size;
		if (addr + *w_size >= mini->start_address &&
			addr + *w_size < x) {
			if (mini->perm >= 2 && mini->perm != 4) {
				unsigned long x = addr + *w_size -
				mini->start_address;
				unsigned long bytes_to_write =
				MIN(mini->size - x, *rem_size);
				if (bytes_to_write > 0) {
					if (mini->rw_buffer) {
						free(mini->rw_buffer);
						mini->rw_buffer = NULL;
					}
					mini->rw_buffer = (char *)malloc(bytes_to_write);
					DIE(!mini->rw_buffer, "mini->rw_buffer malloc failed");
					mini->size_buffer = bytes_to_write;
					memcpy(mini->rw_buffer, data + *w_size, bytes_to_write);
					*w_size += bytes_to_write;
					*rem_size -= bytes_to_write;
				}
			} else {
				printf("Invalid permissions for write.\n");
				while (mini) {
					if (mini->rw_buffer) {
						free(mini->rw_buffer);
						mini->rw_buffer = NULL;
					}
					mini = mini->prev;
				}
			}
		}
		if (mini)
			mini = mini->next;
	}
}

void write(arena_t *arena, const unsigned long address, int size, char *data)
{
	block_t *node = arena->alloc_list->head;
	int written_size = 0;
	while (node && written_size < size) {
		if (address >= node->start_address) {
			list_t *list = node->miniblock_list;
			miniblock_t *mini = list->head;
			int remaining_size = size;
			if (mini->perm == 2 || mini->perm == 3 || mini->perm == 6) {
				if (address + size > node->start_address + node->size &&
					address <= node->start_address + node->size) {
					printf("Warning: size was bigger "
					"than the block size. Writing %ld "
					"characters.\n", node->size);
					size = node->size;
				}
				w_mini(mini, &remaining_size, &written_size, address, data);
			} else {
				printf("Invalid permissions for write.\n");
			}
		}
		node = node->next;
	}
}

void pmap(arena_t *arena)
{
	block_t *curr;
	curr = arena->alloc_list->head;
	unsigned long i = 1;
	if (arena->alloc_list->size == 0)
		arena->free_mem = arena->arena_size;
	printf("Total memory: 0x%lX bytes\n", arena->arena_size);
	printf("Free memory: 0x%lX bytes\n", arena->free_mem);
	printf("Number of allocated blocks: %d\n", arena->alloc_list->size);
	printf("Number of allocated miniblocks: %ld\n", arena->number_miniblocks);
	while (curr) {
		miniblock_t *node;
		list_t *list;
		if(curr->miniblock_list)
		list = curr->miniblock_list;
		node = list->head;
		printf("\nBlock %ld begin\n", i);
		printf("Zone: 0x%lX - ", curr->start_address);
		printf("0x%lX\n", (curr->start_address + curr->size));
		unsigned long j = 1;
		while (node) {
			char perm[4];
			perm[0] = '-';
			perm[1] = '-';
			perm[2] = '-';
			printf("Miniblock %ld:\t\t0x%lX\t\t-\t\t", j, node->start_address);
			 printf("0x%lX\t\t| RW-\n",node->start_address+node->size);
			
			printf("0x%lX\t\t| ", node->start_address + node->size);
			int x = node->perm;
			if (x - 4 >= 0) {
				perm[2] = 'X';
				x = x - 4;
			}
			if (x - 2 >= 0) {
				perm[1] = 'W';
				x = x - 2;
			}
			if (x - 1 >= 0) {
				perm[0] = 'R';
				x = x - 1;
			}
			perm[3] = '\0';
			printf("%s\n", perm);
			node = node->next;
			j++;
		}
		printf("Block %ld end\n", i);
		curr = curr->next;
		i++;
	}
}

void mprotect(arena_t *arena, unsigned long address, char *permission)
{
	block_t *node = arena->alloc_list->head;
	int stop = 0;
	while (node && !stop) {
		list_t *list = node->miniblock_list;
		miniblock_t *mini = list->head;
		while (mini && !stop) {
			if (mini->start_address == address) {
				mini->perm = 0;
				if (permission[0] == 'R') {
					mini->perm = mini->perm + 1;
					node->no_read = 0;
				} else {
					node->no_read = 1;
				}
				if (permission[1] == 'W')
					mini->perm = mini->perm + 2;
				if (permission[2] == 'X')
					mini->perm = mini->perm + 4;
				stop = 1;
			}
			mini = mini->next;
		}
		node = node->next;
	}
	if (stop == 0)
		printf("Invalid address for mprotect.\n");
}

void read_mmprotect(char *perm, char *s)
{
	for (int i = 0; i <= 2; i++)
		perm[i] = '-';
	char *p;
	p = strtok(s, " |\n");
	if (!p) {
		if (strcmp(p, "PROT_READ") == 0)
			perm[0] = 'R';
		else if (strcmp(p, "PROT_WRITE") == 0)
			perm[1] = 'W';
		else if (strcmp(p, "PROT_EXEC") == 0)
			perm[2] = 'X';
	}
	while (p) {
		if (strcmp(p, "PROT_READ") == 0)
			perm[0] = 'R';
		else if (strcmp(p, "PROT_WRITE") == 0)
			perm[1] = 'W';
		else if (strcmp(p, "PROT_EXEC") == 0)
			perm[2] = 'X';
		p = strtok(NULL, " |\n");
	}
}

int main(void)
{
	char command[256];
	scanf("%s", command);
	arena_t *arena;
	while (strcmp(command, "DEALLOC_ARENA") != 0) {
		if (strcmp(command, "ALLOC_ARENA") == 0) {
			unsigned long dim;
			scanf("%lu", &dim);
			arena = alloc_arena(dim);
		} else if (strcmp(command, "ALLOC_BLOCK") == 0) {
			unsigned long dim, size;
			scanf("%lu %lu", &dim, &size);
			alloc_block(arena, dim, size);
		} else if (strcmp(command, "PMAP") == 0) {
			pmap(arena);
		} else if (strcmp(command, "FREE_BLOCK") == 0) {
			free_block(arena);
		} else if (strcmp(command, "WRITE") == 0) {
			unsigned long dim;
			unsigned long address;
			char *data;
			scanf("%lu", &address);
			scanf("%lu", &dim);
			data = malloc(dim);
			int cp = 0;
			char garbage;
			if (dim != 0)
				garbage = fgetc(stdin);
			while (cp != dim) {
				char c = fgetc(stdin);
				data[cp] = c;
				cp++;
			}
			data[dim] = '\0';
			if (arena->number_miniblocks == 0)
				printf("Invalid address for write.\n");
			else
				write(arena, address, dim, data);
			free(data);
		} else if (strcmp("READ", command) == 0) {
			unsigned long addr, dim;
			char s[256];
			fgets(s, 256, stdin);
			int x = 0;
			if (arena->number_miniblocks == 0) {
				printf("Invalid address for read.\n");
			} else {
				for (int i = 0; i < strlen(s); i++)
					if (s[i] == ' ')
						x++;
				if (x == 2) {
					char *p = strtok(s, " ");
					addr = atoi(p);
					p = strtok(NULL, " ");
					dim = atoi(p);
					read(arena, addr, dim);
				} else {
					printf("Invalid address for read.\n");
				}
			}
		} else if (strcmp("MPROTECT", command) == 0) {
			unsigned long addr;
			scanf("%ld", &addr);
			char *s, perm[4];
			s = malloc(256);
			fgets(s, 256, stdin);
			read_mmprotect(perm, s);
			mprotect(arena, addr, perm);
			free(s);
		} else {
			printf("Invalid command. Please try again.\n");
		}
		scanf("%s", command);
	}
	dealloc_arena(arena);
	return 0;
}
