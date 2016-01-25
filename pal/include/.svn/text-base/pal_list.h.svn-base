#ifndef _PALI_LIST_H_
#define _PALI_LIST_H_

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */
struct pal_list_head {
	struct pal_list_head *next, *prev;
};

#define PAL_LIST_HEAD_INIT(name) { &(name), &(name) }

#define PAL_LIST_HEAD(name) \
	struct pal_list_head name = PAL_LIST_HEAD_INIT(name)

static inline void PAL_INIT_LIST_HEAD(struct pal_list_head *list)
{
	list->next = list;
	list->prev = list;
}

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __pal_list_add(struct pal_list_head *new,
			      struct pal_list_head *prev,
			      struct pal_list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * pal_list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void pal_list_add(struct pal_list_head *new, struct pal_list_head *head)
{
	__pal_list_add(new, head, head->next);
}


/**
 * pal_list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void pal_list_add_tail(struct pal_list_head *new, struct pal_list_head *head)
{
	__pal_list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __pal_list_del(struct pal_list_head * prev, struct pal_list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * pal_list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: pal_list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void pal_list_del(struct pal_list_head *entry)
{
	__pal_list_del(entry->prev, entry->next);
}

/**
 * pal_list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int pal_list_empty(const struct pal_list_head *head)
{
	return head->next == head;
}

/**
 * pal_list_entry - get the struct for this entry
 * @ptr:	the &struct pal_list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the pal_list_struct within the struct.
 */
#define pal_list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * pal_list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the pal_list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define pal_list_first_entry(ptr, type, member) \
	pal_list_entry((ptr)->next, type, member)

/**
 * pal_list_for_each	-	iterate over a list
 * @pos:	the &struct pal_list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define pal_list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * __pal_list_for_each	-	iterate over a list
 * @pos:	the &struct pal_list_head to use as a loop cursor.
 * @head:	the head for your list.
 *
 * This variant doesn't differ from pal_list_for_each() any more.
 * We don't do prefetching in either case.
 */
#define __pal_list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * pal_list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct pal_list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define pal_list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * pal_list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct pal_list_head to use as a loop cursor.
 * @n:		another &struct pal_list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define pal_list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * pal_list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the pal_list_struct within the struct.
 */
#define pal_list_for_each_entry(pos, head, member)				\
	for (pos = pal_list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = pal_list_entry(pos->member.next, typeof(*pos), member))

/**
  * list_for_each_entry_reverse - iterate backwards over list of given type.
  * @pos:	the type * to use as a loop cursor.
  * @head:	the head for your list.
  * @member: the name of the list_struct within the struct.
  */
#define pal_list_for_each_entry_reverse(pos, head, member)			\
	for (pos = pal_list_entry((head)->prev, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = pal_list_entry(pos->member.prev, typeof(*pos), member))

/*
 * @brief iterate over list of given type safe against removal of list entry
 * @param pos	The type * to use as a loop cursor.
 * @param n	Another type * to use as temporary storage
 * @param head	The head for your list.
 * @param Member	The name of the pal_list_struct within the struct.
 */
#define pal_list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = pal_list_entry((head)->next, typeof(*pos), member),	\
		n = pal_list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = pal_list_entry(n->member.next, typeof(*n), member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member: the name of the list_struct within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define pal_list_for_each_entry_continue_reverse(pos, head, member)		\
		for (pos = pal_list_entry(pos->member.prev, typeof(*pos), member);	\
			 &pos->member != (head);	\
			 pos = pal_list_entry(pos->member.prev, typeof(*pos), member))

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */
struct pal_hlist_head {
	struct pal_hlist_node *first;
};

struct pal_hlist_node {
	struct pal_hlist_node *next, **pprev;
};

#define PAL_HLIST_HEAD_INIT { .first = NULL }
#define PAL_HLIST_HEAD(name) struct pal_hlist_head name = {  .first = NULL }
#define PAL_INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void PAL_INIT_HLIST_NODE(struct pal_hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int pal_hlist_unhashed(const struct pal_hlist_node *h)
{
	return !h->pprev;
}

static inline int pal_hlist_empty(const struct pal_hlist_head *h)
{
	return !h->first;
}

static inline void __pal_hlist_del(struct pal_hlist_node *n)
{
	struct pal_hlist_node *next = n->next;
	struct pal_hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void pal_hlist_del(struct pal_hlist_node *n)
{
	__pal_hlist_del(n);
}

static inline void pal_hlist_add_head(struct pal_hlist_node *n, struct pal_hlist_head *h)
{
	struct pal_hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

/* next must be != NULL */
static inline void pal_hlist_add_before(struct pal_hlist_node *n,
					struct pal_hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void pal_hlist_add_after(struct pal_hlist_node *n,
					struct pal_hlist_node *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}

#define pal_hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define pal_hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define pal_hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

/**
 * pal_hlist_for_each_entry	- iterate over list of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct pal_hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the pal_hlist_node within the struct.
 */
#define pal_hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos &&							 \
		({ tpos = pal_hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
		
#define pal_hlist_for_each_entry_constant(tpos, pos, head, member)		 \
	for (pos = (head)->first;					 \
	     pos &&							 \
		({ tpos = container_of_constant(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * pal_hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct pal_hlist_node to use as a loop cursor.
 * @n:		another &struct pal_hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the pal_hlist_node within the struct.
 */
#define pal_hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = pal_hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)


#endif
