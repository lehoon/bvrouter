#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "route.h"
#include "pal_error.h"
#include "pal_utils.h"
#include "pal_byteorder.h"
#include "pal_malloc.h"
#include "pal_slab.h"

static struct pal_slab *route_table_slab = NULL;
static struct pal_slab *leaf_info_slab = NULL;
static struct pal_slab *leaf_slab = NULL;

#define WARN_ON(cond) \
	do { \
		if (cond) { \
			PAL_WARNING("Warning func:%s, line:%d\n", \
					__FUNCTION__, __LINE__); \
		} \
	} while(0)
		
#define BUG_ON(cond) \
	do { \
		if (cond) { \
			PAL_PANIC("Warning func:%s, line:%d\n", \
					__FUNCTION__, __LINE__); \
		} \
	} while(0)

static const int halve_threshold = 25;
static const int inflate_threshold = 50;
static const int halve_threshold_root = 15;
static const int inflate_threshold_root = 30;

static struct rt_trie_node *resize(struct rt_trie_node **t, struct tnode *tn);

/*
 * __fls: find last set bit in word
 * @word: The word to search
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 */
static inline unsigned long __fls(unsigned long word)
{
	asm("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return word;
}

static inline uint32_t inet_make_mask(int logmask)
{
	if (logmask)
		return pal_htonl(~((1<<(32-logmask))-1));
	return 0;
}

static inline void check_tnode(const struct tnode *tn)
{
	WARN_ON(tn && tn->pos+tn->bits > 32);
}


static inline int tkey_sub_equals(t_key a, int offset, int bits, t_key b)
{
	if (bits == 0 || offset >= (int)KEYLENGTH)
		return 1;
	bits = bits > (int)KEYLENGTH ? (int)KEYLENGTH : bits;
	return ((a ^ b) << offset) >> (KEYLENGTH - bits) == 0;
}

static inline struct rt_trie_node *tnode_get_child(const struct tnode *tn, unsigned int i)
{
	BUG_ON(i >= 1U << tn->bits);

	return tn->child[i];
}

static inline t_key tkey_extract_bits(t_key a, unsigned int offset, unsigned int bits)
{
	if (offset < KEYLENGTH)
		return ((t_key)(a << offset)) >> (KEYLENGTH - bits);
	else
		return 0;
}

static inline struct tnode *node_parent(const struct rt_trie_node *node)
{
	return (struct tnode *)(node->parent & ~NODE_TYPE_MASK);
}

static inline int tkey_equals(t_key a, t_key b)
{
	return a == b;
}

static struct leaf_info *leaf_info_new(uint32_t plen)
{
	struct leaf_info *li = pal_slab_alloc(leaf_info_slab);
	if (li) {
		li->plen = plen;
		li->mask_plen = pal_ntohl(inet_make_mask(plen));
	}
	return li;
}

static void insert_leaf_info(struct pal_hlist_head *head, struct leaf_info *new)
{
	struct pal_hlist_node *hlist;
	struct leaf_info *li = NULL, *last = NULL;

	if (pal_hlist_empty(head)) {
		pal_hlist_add_head(&new->hlist, head);
	} else {
		pal_hlist_for_each_entry(li, hlist, head, hlist) {
			if (new->plen > li->plen)
				break;

			last = li;
		}
		if (last)
			pal_hlist_add_after(&last->hlist, &new->hlist);
		else
			pal_hlist_add_before(&new->hlist, &li->hlist);
	}
}

static struct leaf *leaf_new(void)
{
	struct leaf *l;

	l = (struct leaf *)pal_slab_alloc(leaf_slab);
	if (l) {
		l->node.parent = T_LEAF;
		PAL_INIT_HLIST_HEAD(&l->list);
	}
	return l;
}

static inline void free_leaf(struct leaf *l)
{
	pal_slab_free(l);
}

/* Same as rcu_assign_pointer
 * but that macro() assumes that value is a pointer.
 */
static inline void node_set_parent(struct rt_trie_node *node, struct tnode *ptr)
{
	node->parent = (unsigned long)ptr | NODE_TYPE(node);
}

/*
 * Check whether a tnode 'n' is "full", i.e. it is an internal node
 * and no bits are skipped. See discussion in dyntree paper p. 6
 */
static inline int tnode_full(const struct tnode *tn, const struct rt_trie_node *n)
{
	if (n == NULL || IS_LEAF(n))
		return 0;

	return ((const struct tnode *)n)->pos == tn->pos + tn->bits;
}

/*
 * Add a child at position i overwriting the old value.
 * Update the value of full_children and empty_children.
 */
static void tnode_put_child_reorg(struct tnode *tn, int i, struct rt_trie_node *n,
				  int wasfull)
{
	struct rt_trie_node *chi = tn->child[i];
	int isfull;

	BUG_ON(i >= 1<<tn->bits);

	/* update emptyChildren */
	if (n == NULL && chi != NULL)
		tn->empty_children++;
	else if (n != NULL && chi == NULL)
		tn->empty_children--;

	/* update fullChildren */
	if (wasfull == -1)
		wasfull = tnode_full(tn, chi);

	isfull = tnode_full(tn, n);
	if (wasfull && !isfull)
		tn->full_children--;
	else if (!wasfull && isfull)
		tn->full_children++;

	if (n)
		node_set_parent(n, tn);

	tn->child[i] = n;
}

static inline void put_child(struct tnode *tn, int i,
			     struct rt_trie_node *n)
{
	tnode_put_child_reorg(tn, i, n, -1);
}

static inline int tkey_mismatch(t_key a, int offset, t_key b)
{
	t_key diff = a ^ b;
	int i = offset;

	if (!diff)
		return 0;
	while ((diff << i) >> (KEYLENGTH-1) == 0)
		i++;
	return i;
}

static struct tnode *tnode_alloc(size_t size)
{
	struct tnode *n;
	n = pal_malloc(size);
	if(n){
		memset(n,0,size);
	}
	return n;
}

static struct tnode *tnode_new(t_key key, int pos, int bits)
{
	size_t sz = sizeof(struct tnode) + (sizeof(struct rt_trie_node *) << bits);
	struct tnode *tn = tnode_alloc(sz);

	if (tn) {
		tn->node.parent = T_TNODE;
		tn->pos = pos;
		tn->bits = bits;
		tn->node.key = key;
		tn->full_children = 0;
		tn->empty_children = 1<<bits;
	}

	return tn;
}

static inline void free_leaf_info(struct leaf_info *leaf)
{
	pal_slab_free(leaf);
}

static inline int tnode_child_length(const struct tnode *tn)
{
	return 1 << tn->bits;
}

static void tnode_free_safe(struct tnode *tn)
{
	BUG_ON(IS_LEAF(tn));
	pal_free(tn);
	//tn->tnode_free = tnode_free_head;
	//tnode_free_head = tn;
	//tnode_free_size += sizeof(struct tnode) +
	//		   (sizeof(struct rt_trie_node *) << tn->bits);
}

static inline void tnode_free(struct tnode *tn)
{
	if (IS_LEAF(tn))
		free_leaf((struct leaf *) tn);
	else
		pal_free(tn);
}

static void tnode_clean_free(struct tnode *tn)
{
	int i;
	struct tnode *tofree;

	for (i = 0; i < tnode_child_length(tn); i++) {
		tofree = (struct tnode *)tn->child[i];
		if (tofree)
			tnode_free(tofree);
	}
	tnode_free(tn);
}

static struct tnode *inflate(struct rt_trie_node **t, struct tnode *tn)
{
	struct tnode *oldtnode = tn;
	int olen = tnode_child_length(tn);
	int i;

	tn = tnode_new(oldtnode->node.key, oldtnode->pos, oldtnode->bits + 1);

	if (!tn)
		return NULL;

	/*
	 * Preallocate and store tnodes before the actual work so we
	 * don't get into an inconsistent state if memory allocation
	 * fails. In case of failure we return the oldnode and  inflate
	 * of tnode is ignored.
	 */

	for (i = 0; i < olen; i++) {
		struct tnode *inode;

		inode = (struct tnode *) tnode_get_child(oldtnode, i);
		if (inode &&
		    IS_TNODE(inode) &&
		    inode->pos == oldtnode->pos + oldtnode->bits &&
		    inode->bits > 1) {
			struct tnode *left, *right;
			t_key m = ~0U << (KEYLENGTH - 1) >> inode->pos;

			left = tnode_new(inode->node.key&(~m), inode->pos + 1,
					 inode->bits - 1);
			if (!left)
				goto nomem;

			right = tnode_new(inode->node.key|m, inode->pos + 1,
					  inode->bits - 1);

			if (!right) {
				tnode_free(left);
				goto nomem;
			}

			put_child(tn, 2*i, (struct rt_trie_node *) left);
			put_child(tn, 2*i+1, (struct rt_trie_node *) right);
		}
	}

	for (i = 0; i < olen; i++) {
		struct tnode *inode;
		struct rt_trie_node *node = tnode_get_child(oldtnode, i);
		struct tnode *left, *right;
		int size, j;

		/* An empty child */
		if (node == NULL)
			continue;

		/* A leaf or an internal node with skipped bits */

		if (IS_LEAF(node) || ((struct tnode *) node)->pos >
		   tn->pos + tn->bits - 1) {
			if (tkey_extract_bits(node->key,
					      oldtnode->pos + oldtnode->bits,
					      1) == 0)
				put_child(tn, 2*i, node);
			else
				put_child(tn, 2*i+1, node);
			continue;
		}

		/* An internal node with two children */
		inode = (struct tnode *) node;

		if (inode->bits == 1) {
			put_child(tn, 2*i, inode->child[0]);
			put_child(tn, 2*i+1, inode->child[1]);

			tnode_free_safe(inode);
			continue;
		}

		/* An internal node with more than two children */

		/* We will replace this node 'inode' with two new
		 * ones, 'left' and 'right', each with half of the
		 * original children. The two new nodes will have
		 * a position one bit further down the key and this
		 * means that the "significant" part of their keys
		 * (see the discussion near the top of this file)
		 * will differ by one bit, which will be "0" in
		 * left's key and "1" in right's key. Since we are
		 * moving the key position by one step, the bit that
		 * we are moving away from - the bit at position
		 * (inode->pos) - is the one that will differ between
		 * left and right. So... we synthesize that bit in the
		 * two  new keys.
		 * The mask 'm' below will be a single "one" bit at
		 * the position (inode->pos)
		 */

		/* Use the old key, but set the new significant
		 *   bit to zero.
		 */

		left = (struct tnode *) tnode_get_child(tn, 2*i);
		put_child(tn, 2*i, NULL);

		BUG_ON(!left);

		right = (struct tnode *) tnode_get_child(tn, 2*i+1);
		put_child(tn, 2*i+1, NULL);

		BUG_ON(!right);

		size = tnode_child_length(left);
		for (j = 0; j < size; j++) {
			put_child(left, j, inode->child[j]);
			put_child(right, j, inode->child[j + size]);
		}
		put_child(tn, 2*i, resize(t, left));
		put_child(tn, 2*i+1, resize(t, right));

		tnode_free_safe(inode);
	}
	tnode_free_safe(oldtnode);
	return tn;
nomem:
	tnode_clean_free(tn);
	return NULL;
}

static struct tnode *halve(struct rt_trie_node **t, struct tnode *tn)
{
	struct tnode *oldtnode = tn;
	struct rt_trie_node *left, *right;
	int i;
	int olen = tnode_child_length(tn);

	tn = tnode_new(oldtnode->node.key, oldtnode->pos, oldtnode->bits - 1);

	if (!tn)
		return NULL;

	/*
	 * Preallocate and store tnodes before the actual work so we
	 * don't get into an inconsistent state if memory allocation
	 * fails. In case of failure we return the oldnode and halve
	 * of tnode is ignored.
	 */

	for (i = 0; i < olen; i += 2) {
		left = tnode_get_child(oldtnode, i);
		right = tnode_get_child(oldtnode, i+1);

		/* Two nonempty children */
		if (left && right) {
			struct tnode *newn;

			newn = tnode_new(left->key, tn->pos + tn->bits, 1);

			if (!newn)
				goto nomem;

			put_child(tn, i/2, (struct rt_trie_node *)newn);
		}

	}

	for (i = 0; i < olen; i += 2) {
		struct tnode *newBinNode;

		left = tnode_get_child(oldtnode, i);
		right = tnode_get_child(oldtnode, i+1);

		/* At least one of the children is empty */
		if (left == NULL) {
			if (right == NULL)    /* Both are empty */
				continue;
			put_child(tn, i/2, right);
			continue;
		}

		if (right == NULL) {
			put_child(tn, i/2, left);
			continue;
		}

		/* Two nonempty children */
		newBinNode = (struct tnode *) tnode_get_child(tn, i/2);
		put_child(tn, i/2, NULL);
		put_child(newBinNode, 0, left);
		put_child(newBinNode, 1, right);
		put_child(tn, i/2, resize(t, newBinNode));
	}
	tnode_free_safe(oldtnode);
	return tn;
nomem:
	tnode_clean_free(tn);
	return NULL;
}


#define MAX_WORK 10
static struct rt_trie_node *resize(struct rt_trie_node **t, struct tnode *tn)
{
	int i;
	struct tnode *old_tn;
	int inflate_threshold_use;
	int halve_threshold_use;
	int max_work;

	if (!tn)
		return NULL;

	/* No children */
	if (tn->empty_children == (unsigned)tnode_child_length(tn)) {
		tnode_free_safe(tn);
		return NULL;
	}
	/* One child */
	if (tn->empty_children == (unsigned)tnode_child_length(tn) - 1)
		goto one_child;
	/*
	 * Double as long as the resulting node has a number of
	 * nonempty nodes that are above the threshold.
	 */

	/*
	 * From "Implementing a dynamic compressed trie" by Stefan Nilsson of
	 * the Helsinki University of Technology and Matti Tikkanen of Nokia
	 * Telecommunications, page 6:
	 * "A node is doubled if the ratio of non-empty children to all
	 * children in the *doubled* node is at least 'high'."
	 *
	 * 'high' in this instance is the variable 'inflate_threshold'. It
	 * is expressed as a percentage, so we multiply it with
	 * tnode_child_length() and instead of multiplying by 2 (since the
	 * child array will be doubled by inflate()) and multiplying
	 * the left-hand side by 100 (to handle the percentage thing) we
	 * multiply the left-hand side by 50.
	 *
	 * The left-hand side may look a bit weird: tnode_child_length(tn)
	 * - tn->empty_children is of course the number of non-null children
	 * in the current node. tn->full_children is the number of "full"
	 * children, that is non-null tnodes with a skip value of 0.
	 * All of those will be doubled in the resulting inflated tnode, so
	 * we just count them one extra time here.
	 *
	 * A clearer way to write this would be:
	 *
	 * to_be_doubled = tn->full_children;
	 * not_to_be_doubled = tnode_child_length(tn) - tn->empty_children -
	 *     tn->full_children;
	 *
	 * new_child_length = tnode_child_length(tn) * 2;
	 *
	 * new_fill_factor = 100 * (not_to_be_doubled + 2*to_be_doubled) /
	 *      new_child_length;
	 * if (new_fill_factor >= inflate_threshold)
	 *
	 * ...and so on, tho it would mess up the while () loop.
	 *
	 * anyway,
	 * 100 * (not_to_be_doubled + 2*to_be_doubled) / new_child_length >=
	 *      inflate_threshold
	 *
	 * avoid a division:
	 * 100 * (not_to_be_doubled + 2*to_be_doubled) >=
	 *      inflate_threshold * new_child_length
	 *
	 * expand not_to_be_doubled and to_be_doubled, and shorten:
	 * 100 * (tnode_child_length(tn) - tn->empty_children +
	 *    tn->full_children) >= inflate_threshold * new_child_length
	 *
	 * expand new_child_length:
	 * 100 * (tnode_child_length(tn) - tn->empty_children +
	 *    tn->full_children) >=
	 *      inflate_threshold * tnode_child_length(tn) * 2
	 *
	 * shorten again:
	 * 50 * (tn->full_children + tnode_child_length(tn) -
	 *    tn->empty_children) >= inflate_threshold *
	 *    tnode_child_length(tn)
	 *
	 */

	check_tnode(tn);

	/* Keep root node larger  */

	if (!node_parent((struct rt_trie_node *)tn)) {
		inflate_threshold_use = inflate_threshold_root;
		halve_threshold_use = halve_threshold_root;
	} else {
		inflate_threshold_use = inflate_threshold;
		halve_threshold_use = halve_threshold;
	}

	max_work = MAX_WORK;
	while ((tn->full_children > 0 &&  max_work-- &&
		50 * (tn->full_children + tnode_child_length(tn)
		      - tn->empty_children)
		>= inflate_threshold_use * (unsigned)tnode_child_length(tn))) {

		old_tn = tn;
		tn = inflate(t, tn);

		if (tn == NULL) {
			tn = old_tn;
			break;
		}
	}

	check_tnode(tn);

	/* Return if at least one inflate is run */
	if (max_work != MAX_WORK)
		return (struct rt_trie_node *) tn;

	/*
	 * Halve as long as the number of empty children in this
	 * node is above threshold.
	 */

	max_work = MAX_WORK;
	while (tn->bits > 1 &&  max_work-- &&
	       100 * (tnode_child_length(tn) - tn->empty_children) <
	       halve_threshold_use * (unsigned)tnode_child_length(tn)) {

		old_tn = tn;
		tn = halve(t, tn);
		if (tn == NULL) {
			tn = old_tn;
			break;
		}
	}


	/* Only one child remains */
	if (tn->empty_children == (unsigned)tnode_child_length(tn) - 1) {
one_child:
		for (i = 0; i < tnode_child_length(tn); i++) {
			struct rt_trie_node *n;

			n = tn->child[i];
			if (!n)
				continue;

			/* compress one level */

			node_set_parent(n, NULL);
			tnode_free_safe(tn);
			return n;
		}
	}
	return (struct rt_trie_node *) tn;
}

static void trie_rebalance(struct rt_trie_node **t, struct tnode *tn)
{
	int wasfull;
	t_key cindex, key;
	struct tnode *tp;

	key = tn->node.key;

	while (tn != NULL && (tp = node_parent((struct rt_trie_node *)tn)) != NULL) {
		cindex = tkey_extract_bits(key, tp->pos, tp->bits);
		wasfull = tnode_full(tp, tnode_get_child(tp, cindex));
		tn = (struct tnode *)resize(t, tn);

		tnode_put_child_reorg(tp, cindex,
				      (struct rt_trie_node *)tn, wasfull);

		tp = node_parent((struct rt_trie_node *) tn);
		if (!tp)
			*t = (struct rt_trie_node *)tn;

		//tnode_free_flush();
		if (!tp)
			break;
		tn = tp;
	}

	/* Handle last (top) tnode */
	if (IS_TNODE(tn))
		tn = (struct tnode *)resize(t, tn);

	*t = (struct rt_trie_node *)tn;
	//tnode_free_flush();
}

static struct leaf_info *fib_insert_node(struct rt_trie_node **t, uint32_t key, uint32_t plen)
{
	int pos, newpos;
	struct tnode *tp = NULL, *tn = NULL;
	struct rt_trie_node *n;
	struct leaf *l;
	int missbit;
	struct leaf_info *li, *li_ret = NULL;
	t_key cindex;

	if(!t)
		return NULL;
	
	pos = 0;
	n = *t;

	/* If we point to NULL, stop. Either the tree is empty and we should
	 * just put a new leaf in if, or we have reached an empty child slot,
	 * and we should just put our new leaf in that.
	 * If we point to a T_TNODE, check if it matches our key. Note that
	 * a T_TNODE might be skipping any number of bits - its 'pos' need
	 * not be the parent's 'pos'+'bits'!
	 *
	 * If it does match the current key, get pos/bits from it, extract
	 * the index from our key, push the T_TNODE and walk the tree.
	 *
	 * If it doesn't, we have to replace it with a new T_TNODE.
	 *
	 * If we point to a T_LEAF, it might or might not have the same key
	 * as we do. If it does, just change the value, update the T_LEAF's
	 * value, and return it.
	 * If it doesn't, we need to replace it with a T_TNODE.
	 */

	while (n != NULL &&  NODE_TYPE(n) == T_TNODE) {
		tn = (struct tnode *) n;

		check_tnode(tn);

		if (tkey_sub_equals(tn->node.key, pos, tn->pos-pos, key)) {
			tp = tn;
			pos = tn->pos + tn->bits;
			n = tnode_get_child(tn,
					    tkey_extract_bits(key,
							      tn->pos,
							      tn->bits));

			BUG_ON(n && node_parent(n) != tn);
		} else
			break;
	}

	/*
	 * n  ----> NULL, LEAF or TNODE
	 *
	 * tp is n's (parent) ----> NULL or TNODE
	 */

	BUG_ON(tp && IS_LEAF(tp));

	/* Case 1: n is a leaf. Compare prefixes */

	if (n != NULL && IS_LEAF(n) && tkey_equals(key, n->key)) {
		l = (struct leaf *) n;
		li = leaf_info_new(plen);

		if (!li)
			return NULL;

		li_ret = li;
		li->l = l;
		insert_leaf_info(&l->list, li);
		goto done;
	}
	l = leaf_new();

	if (!l)
		return NULL;

	l->node.key = key;
	li = leaf_info_new(plen);

	if (!li) {
		free_leaf(l);
		return NULL;
	}

	li_ret = li;	
	li->l = l;
	insert_leaf_info(&l->list, li);

	if (*t && n == NULL) {
		/* Case 2: n is NULL, and will just insert a new leaf */

		node_set_parent((struct rt_trie_node *)l, tp);

		cindex = tkey_extract_bits(key, tp->pos, tp->bits);
		put_child(tp, cindex, (struct rt_trie_node *)l);
	} else {
		/* Case 3: n is a LEAF or a TNODE and the key doesn't match. */
		/*
		 *  Add a new tnode here
		 *  first tnode need some special handling
		 */

		if (tp)
			pos = tp->pos+tp->bits;
		else
			pos = 0;

		if (n) {
			newpos = tkey_mismatch(key, pos, n->key);
			tn = tnode_new(n->key, newpos, 1);
		} else {
			newpos = 0;
			tn = tnode_new(key, newpos, 1); /* First tnode */
		}

		if (!tn) {
			free_leaf_info(li);
			free_leaf(l);
			return NULL;
		}

		node_set_parent((struct rt_trie_node *)tn, tp);

		missbit = tkey_extract_bits(key, newpos, 1);
		put_child(tn, missbit, (struct rt_trie_node *)l);
		put_child(tn, 1-missbit, n);

		if (tp) {
			cindex = tkey_extract_bits(key, tp->pos, tp->bits);
			put_child(tp, cindex, (struct rt_trie_node *)tn);
		} else {
			*t = (struct rt_trie_node *)tn;
			tp = tn;
		}
	}

	if (tp && tp->pos + tp->bits > 32)
		printf("fib_trie tp=%p pos=%d, bits=%d, key=%0x plen=%d\n",
			tp, tp->pos, tp->bits, key, plen);

	/* Rebalance the trie */

	trie_rebalance(t, tp);
done:
	return li_ret;
}

/*lpm check*/
static int check_leaf(struct leaf *l, t_key key,int route_type,struct fib_result *res)
{
	struct leaf_info *li;
	struct pal_hlist_head *hhead = &l->list;
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(li, hnode, hhead, hlist) {
		if (l->node.key != (key & li->mask_plen))
			continue;

		if(!(li->type & route_type))
			continue;
		
		res->next_hop = li->next_hop;
		res->route_type = li->type;
		res->prefix	= li->prefix;
		res->prefixlen = li->plen;
		res->sip = li->sip;
		res->port_dev = li->port_dev;
		res->li = li;
		return 0;
	}

	return -1;
}

static inline t_key mask_pfx(t_key k, unsigned int l)
{
	return (l == 0) ? 0 : k >> (KEYLENGTH-l) << (KEYLENGTH-l);
}

/*
 * @brief Create a new routing table.
 * @return Pointer to the new routing table, or NULL on failure
 */
struct route_table *pal_rtable_new(void)
{
	struct route_table *rt;
	rt = pal_slab_alloc(route_table_slab);
	if(rt){
		rt->trie = NULL;
		rt->route_entry_count = 0;
		rt->default_route_flag = 0;
	}
	
	return rt;
}

void pal_rtable_destroy(struct route_table *rtable)
{
	if(rtable->route_entry_count != 0)
		PAL_PANIC("route BUG\n");

	pal_slab_free(rtable);
}

static void traverse_trie(const struct rt_trie_node *root, void *reb,
			void (*f)(const struct rt_trie_node *, int,void *))
{
	const struct rt_trie_node *child;
	const struct tnode *tn, *tp;
	int child_index;
	int level;

	if(!root)
		return;
		
	f(root,0,reb);

	if (IS_LEAF(root))
		return;

	level = 1;
	child_index = 0;
	tn = (const struct tnode *)root;
	while (1) {
		for (; child_index < (1 << tn->bits); child_index++) {
			child = tnode_get_child(tn, child_index);
			if (child == NULL)
				continue;

			f(child, level,reb);
			if (IS_LEAF(child))
				continue;

			level++;
			/* child_index will be 0 after child_index++ */
			child_index = -1;
			tn = (const struct tnode *)child;
		}

		if (--level == 0)
			break;
		tp = node_parent(&tn->node);
		child_index = tkey_extract_bits(tn->node.key, tp->pos, tp->bits) + 1;
		tn = tp;
	}
}

static int __pal_route_lookup(const struct route_table *rtable, uint32_t dst,
	int route_type,struct fib_result *res)
{
	int ret;
	struct rt_trie_node *n;
	struct tnode *pn;
	unsigned int pos, bits;
	t_key key = pal_ntohl(dst);
	unsigned int chopped_off;
	t_key cindex = 0;
	unsigned int current_prefix_length = KEYLENGTH;
	struct tnode *cn;
	t_key pref_mismatch;

	n = rtable->trie;
	if (!n)
		goto failed;

	/* Just a leaf? */
	if (IS_LEAF(n)) {
		ret = check_leaf((struct leaf *)n, key,route_type,res);
		goto found;
	}

	pn = (struct tnode *) n;
	chopped_off = 0;

	while (pn) {
		pos = pn->pos;
		bits = pn->bits;

		if (!chopped_off)
			cindex = tkey_extract_bits(mask_pfx(key, current_prefix_length),
						   pos, bits);

		n = tnode_get_child(pn, cindex);

		if (n == NULL) {
			goto backtrace;
		}

		if (IS_LEAF(n)) {
			ret = check_leaf((struct leaf *)n, key,route_type,res);
			if (ret < 0)
				goto backtrace;
			goto found;
		}

		cn = (struct tnode *)n;

		/*
		 * It's a tnode, and we can do some extra checks here if we
		 * like, to avoid descending into a dead-end branch.
		 * This tnode is in the parent's child array at index
		 * key[p_pos..p_pos+p_bits] but potentially with some bits
		 * chopped off, so in reality the index may be just a
		 * subprefix, padded with zero at the end.
		 * We can also take a look at any skipped bits in this
		 * tnode - everything up to p_pos is supposed to be ok,
		 * and the non-chopped bits of the index (se previous
		 * paragraph) are also guaranteed ok, but the rest is
		 * considered unknown.
		 *
		 * The skipped bits are key[pos+bits..cn->pos].
		 */

		/* If current_prefix_length < pos+bits, we are already doing
		 * actual prefix  matching, which means everything from
		 * pos+(bits-chopped_off) onward must be zero along some
		 * branch of this subtree - otherwise there is *no* valid
		 * prefix present. Here we can only check the skipped
		 * bits. Remember, since we have already indexed into the
		 * parent's child array, we know that the bits we chopped of
		 * *are* zero.
		 */

		/* NOTA BENE: Checking only skipped bits
		   for the new node here */

		if (current_prefix_length < pos+bits) {
			if (tkey_extract_bits(cn->node.key, current_prefix_length,
						cn->pos - current_prefix_length)
			    || !(cn->child[0]))
				goto backtrace;
		}

		/*
		 * If chopped_off=0, the index is fully validated and we
		 * only need to look at the skipped bits for this, the new,
		 * tnode. What we actually want to do is to find out if
		 * these skipped bits match our key perfectly, or if we will
		 * have to count on finding a matching prefix further down,
		 * because if we do, we would like to have some way of
		 * verifying the existence of such a prefix at this point.
		 */

		/* The only thing we can do at this point is to verify that
		 * any such matching prefix can indeed be a prefix to our
		 * key, and if the bits in the node we are inspecting that
		 * do not match our key are not ZERO, this cannot be true.
		 * Thus, find out where there is a mismatch (before cn->pos)
		 * and verify that all the mismatching bits are zero in the
		 * new tnode's key.
		 */

		/*
		 * Note: We aren't very concerned about the piece of
		 * the key that precede pn->pos+pn->bits, since these
		 * have already been checked. The bits after cn->pos
		 * aren't checked since these are by definition
		 * "unknown" at this point. Thus, what we want to see
		 * is if we are about to enter the "prefix matching"
		 * state, and in that case verify that the skipped
		 * bits that will prevail throughout this subtree are
		 * zero, as they have to be if we are to find a
		 * matching prefix.
		 */

		pref_mismatch = mask_pfx(cn->node.key ^ key, cn->pos);

		/*
		 * In short: If skipped bits in this node do not match
		 * the search key, enter the "prefix matching"
		 * state.directly.
		 */
		if (pref_mismatch) {
			/* fls(x) = __fls(x) + 1 */
			int mp = KEYLENGTH - __fls(pref_mismatch) - 1;

			if (tkey_extract_bits(cn->node.key, mp, cn->pos - mp) != 0)
				goto backtrace;

			if (current_prefix_length >= cn->pos)
				current_prefix_length = mp;
		}

		pn = (struct tnode *)n; /* Descend */
		chopped_off = 0;
		continue;

backtrace:
		chopped_off++;

		/* As zero don't change the child key (cindex) */
		while ((chopped_off <= pn->bits)
		       && !(cindex & (1<<(chopped_off-1))))
			chopped_off++;

		/* Decrease current_... with bits chopped off */
		if (current_prefix_length > pn->pos + pn->bits - chopped_off)
			current_prefix_length = pn->pos + pn->bits
				- chopped_off;

		/*
		 * Either we do the actual chop off according or if we have
		 * chopped off all bits in this tnode walk up to our parent.
		 */

		if (chopped_off <= pn->bits) {
			cindex &= ~(1 << (chopped_off-1));
		} else {
			struct tnode *parent = node_parent((struct rt_trie_node *) pn);
			if (!parent)
				goto failed;

			/* Get Child's index */
			cindex = tkey_extract_bits(pn->node.key, parent->pos, parent->bits);
			pn = parent;
			chopped_off = 0;

			goto backtrace;
		}
	}
failed:
	ret = -1;
found:
	return ret;
}

static void dump_node(const struct rt_trie_node *n, int level,__unused void *reb)
{
	int i;
	uint32_t mask;
	const struct tnode *tn;
	const struct leaf *l;
	const struct pal_hlist_node *hnode;
	const struct leaf_info *li;

	for (i = 0; i < level; i++) {
		printf("  ");
	}

	if (IS_LEAF(n)) {
		l = (const struct leaf *)n;
		mask = pal_htonl(l->node.key);
		printf("L "NIPQUAD_FMT": ", NIPQUAD(mask));
		pal_hlist_for_each_entry_constant (li, hnode, &l->list, hlist) {
			if (li->type == PAL_ROUTE_COMMON) {
				printf("(/%d->["NIPQUAD_FMT"]) ", li->plen, NIPQUAD(li->next_hop));
			} else if(li->type == PAL_ROUTE_CONNECTED) {
				printf("(/%d->connected:<"NIPQUAD_FMT">) ", li->plen,NIPQUAD(li->sip));
			}else{
				printf("(/%d->local:<"NIPQUAD_FMT">) ", li->plen,NIPQUAD(li->sip));
			}	
		}
		printf("\n");
	} else {
		int j, cnt = 0;
		tn = (const struct tnode *)n;
		printf("T ");
		for (j = 0; j < (1 << tn->bits); j++) {
			if (tnode_get_child(tn, j) != NULL)
				cnt++;
		}
		printf("%d child:\n", cnt);
	}
}

void pal_trie_dump(const struct route_table *rtable)
{
	traverse_trie(rtable->trie,NULL,dump_node);
}

static struct leaf *fib_find_node(struct rt_trie_node **t, uint32_t key)
{
	int pos;
	struct tnode *tn;
	struct rt_trie_node *n;

	pos = 0;
	n = *t;

	while (n != NULL &&  NODE_TYPE(n) == T_TNODE) {
		tn = (struct tnode *) n;

		check_tnode(tn);

		if (tkey_sub_equals(tn->node.key, pos, tn->pos-pos, key)) {
			pos = tn->pos + tn->bits;
			n = tnode_get_child(tn,
						tkey_extract_bits(key,
								  tn->pos,
								  tn->bits));
		} else
			break;
	}
	/* Case we have found a leaf. Compare prefixes */

	if (n != NULL && IS_LEAF(n) && tkey_equals(key, n->key))
		return (struct leaf *)n;

	return NULL;
}

static struct leaf_info *find_leaf_info_lpm(struct leaf *l, uint32_t plen,int route_type)
{
	struct pal_hlist_head *head = &l->list;
	struct leaf_info *li;	
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(li,hnode,head, hlist){
		if (li->plen != plen)
			continue;
		if(!(li->type & route_type))
			continue;

		return li;
	}
	
	return NULL;
}

static struct leaf_info *find_leaf_info_am_nexthop(struct leaf *l, uint32_t plen,int route_type,struct look_up_helper *help)
{
	struct pal_hlist_head *head = &l->list;
	struct leaf_info *li;	
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(li,hnode,head, hlist){
		if (li->plen != plen)
			continue;
		
		if(!(li->type & route_type))
			continue;
		
		if(li->next_hop!=help->next_hop)
			continue;
		
		return li;
	}
	
	return NULL;
}

static struct leaf_info *find_leaf_info_am_sip(struct leaf *l, uint32_t plen,int route_type,struct look_up_helper *help)
{
	struct pal_hlist_head *head = &l->list;
	struct leaf_info *li;	
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(li,hnode,head, hlist){
		if (li->plen != plen)
			continue;
		
		if(!(li->type & route_type))
			continue;
		
		if(li->sip!=help->sip)
			continue;
		
		return li;
	}
	
	return NULL;
}

static struct leaf_info *find_leaf_info(struct leaf *l, uint32_t plen,int route_type,
	int look_up_type,struct look_up_helper *help)
{
	struct leaf_info *li;
	
	switch(look_up_type){
		case LPM_LOOKUP:
			li = find_leaf_info_lpm(l,plen,route_type);
			break;
		case NEXTHOP_AM_LOOKUP:
			li = find_leaf_info_am_nexthop(l,plen,route_type,help);
			break;
		case SIP_AM_LOOKUP:
			li = find_leaf_info_am_sip(l,plen,route_type,help);
			break;
		default:
			return NULL;
	}
		
	return li;
}

/*
 * Remove the leaf and return parent.
 */
static void trie_leaf_remove(struct rt_trie_node **t, struct leaf *l)
{
	struct tnode *tp = node_parent((struct rt_trie_node *) l);

	if (tp) {
		t_key cindex = tkey_extract_bits(l->node.key, tp->pos, tp->bits);
		put_child(tp, cindex, NULL);
		trie_rebalance(t, tp);
	} else
		*t = NULL;

	free_leaf(l);
}

extern  int trie_flush_leaf(struct leaf *l);
int trie_flush_leaf(struct leaf *l)
{
	int found = 0;
	struct pal_hlist_head *lih = &l->list;
	struct pal_hlist_node *tmp;
	struct pal_hlist_node *node; 
	struct leaf_info *li = NULL;

	pal_hlist_for_each_entry_safe(li, node,tmp, lih, hlist) {
		pal_hlist_del(&li->hlist);
		free_leaf_info(li);
		found++;
	}

	
	return found;
}

static void add_leaf_info_to_connect(struct leaf_info *li,
	 struct leaf_info *connect_li)
{
	pal_list_add(&li->route_list,&connect_li->route_list_head);
}

static void remove_leaf_info_from_connect(struct leaf_info *li)
{
	pal_list_del(&li->route_list);
}

static void remove_leaf_info_from_leaf(struct leaf_info *li){
	pal_hlist_del(&li->hlist);
}
		
static int common_route_leaf_info_destroy(struct route_table *t,struct leaf *l,struct leaf_info *li)
{
	remove_leaf_info_from_connect(li);
	remove_leaf_info_from_leaf(li);
	free_leaf_info(li);

		
	/*delete leaf if leaf is empty*/
	if (pal_hlist_empty(&l->list))
		trie_leaf_remove(&t->trie, l);
	
	t->route_entry_count--;
	return 0;
}

static int local_route_leaf_info_destroy(struct route_table *t,struct leaf *l,struct leaf_info *li)
{
	remove_leaf_info_from_leaf(li);
	free_leaf_info(li);

		
	/*delete leaf if leaf is empty*/
	if (pal_hlist_empty(&l->list)){
		trie_leaf_remove(&t->trie, l);
	}
	
	t->route_entry_count--;
	return 0;
}

static void delete_connect_leaf_info(struct route_table *t,struct leaf_info *connect_li)
{
	struct leaf *l;
	struct leaf_info *li;	
	struct pal_list_head *element;

	while (!pal_list_empty(&connect_li->route_list_head)) {
		element = connect_li->route_list_head.next;
		li = pal_list_entry(element, struct leaf_info, route_list);

		if(li->type != PAL_ROUTE_COMMON)
			PAL_PANIC("BUG");
			
		remove_leaf_info_from_connect(li);
		remove_leaf_info_from_leaf(li);

		l = li->l;
		if(!l)
			PAL_PANIC("BUG");
		
		if (pal_hlist_empty(&l->list))
			trie_leaf_remove(&t->trie, l);

		/*this route entry may valid,so route_add again*/
		pal_route_add(t,li->prefix,li->plen,li->next_hop);
		
		free_leaf_info(li);
		t->route_entry_count--;		

	}	
}

static int connect_route_leaf_info_destroy(struct route_table *t,struct leaf *l,struct leaf_info *li)
{
	remove_leaf_info_from_leaf(li);
	if (pal_hlist_empty(&l->list))
		trie_leaf_remove(&t->trie, l);

	delete_connect_leaf_info(t,li);	
	free_leaf_info(li);
		

	t->route_entry_count--;
	return 0;
}

static int leaf_info_destroy(struct route_table *t,struct leaf *l,struct leaf_info *li)
{
	int ret;

	if(!li)
		return -1;
	
	switch(li->type){
		case PAL_ROUTE_COMMON:
			ret = common_route_leaf_info_destroy(t,l,li);
			break;		
		case PAL_ROUTE_LOCAL:
			ret = local_route_leaf_info_destroy(t,l,li);
			break;
		case PAL_ROUTE_CONNECTED:			
			ret = connect_route_leaf_info_destroy(t,l,li);
			break;
		default:
			ret = -1;
	}

	return ret;
}

static struct leaf_info * __fib_find_leaf_info(struct route_table *t,uint32_t key, 
	uint32_t prefix_len,int route_type,int lookup_type,struct look_up_helper *help)
{
	struct leaf *l;
	struct leaf_info *li;
	
	l = fib_find_node(&t->trie, key);
	if (!l)
		return NULL;

	li = find_leaf_info(l, prefix_len,route_type,lookup_type,help);

	return li;
}

static int __pal_route_del(struct route_table *t, uint32_t prefix, uint32_t prefix_len,
	int route_type,int lookup_type,struct look_up_helper *help)
{
	uint32_t key, mask;
	int ret;
	struct leaf *l;	
	struct leaf_info *li;

	if (prefix_len > 32) {
		PAL_ERROR("add route, prefix len to long\n");
		return -EROUTE_WRONG_PREFIX;
	}

	key = pal_ntohl(prefix);
	mask = pal_ntohl(inet_make_mask(prefix_len));
	if (key & ~mask) {
		PAL_ERROR("add route, key and mask does not match\n");
		return -EROUTE_WRONG_NETMASK;
	}

	l = fib_find_node(&t->trie, key);
	if (!l){
		return -EROUTE_CIDR_NOT_EXIST;
    }
	
	li = find_leaf_info(l, prefix_len,route_type,lookup_type,help);
	if (!li) {
		return -EROUTE_CIDR_NOT_EXIST;
    }

	ret = leaf_info_destroy(t,l,li);
	
	return ret;
}

/*
* LPM search
*/
int pal_route_lookup(const struct route_table *rtable, uint32_t dst,struct fib_result *res)
{
	return __pal_route_lookup(rtable,dst,PAL_ROUTE_CONNECTED|PAL_ROUTE_COMMON|PAL_ROUTE_LOCAL,res);
}

/* Add a static route.
 * Assume lock of vport_net is held, so that @vp wouldn't be deleted. */
static int _pal_route_add(struct route_table *t, uint32_t prefix, 
			uint32_t prefixlen, uint32_t nexthop, struct vport *vp)
{
	uint32_t key;
    uint32_t mask;
    uint32_t connect_key;
    uint32_t vport_prefix;
    uint32_t vport_prefixlen;
	struct look_up_helper help;
	struct fib_result res;
	struct leaf_info *li = NULL;
    struct leaf_info *connect_li = NULL;
    struct int_vport *vxlan_port = NULL;

	if (prefixlen > 32) {
		PAL_ERROR("add route, prefix len to long\n");
		return -EROUTE_WRONG_PREFIX;
	}

    if ((nexthop == 0) && (vp == NULL)) {
        PAL_ERROR("add route, one dst(nexthop or vport) at least should be specified\n");
        return -EROUTE_MISS_DST;
    }

	key = pal_ntohl(prefix);
	mask = pal_ntohl(inet_make_mask(prefixlen));
	if (key & ~mask) {
		PAL_ERROR("add route, key and mask does not match\n");
		return -EROUTE_WRONG_NETMASK;
	}

    /* Check if nexthop is reachable, and find connected leaf info. */
    if (vp == NULL) {
        /*check nexthop is reachable*/
        if (__pal_route_lookup(t, nexthop, PAL_ROUTE_CONNECTED,&res) < 0) {
            PAL_ERROR("net unreachable for route "NIPQUAD_FMT"/%d \n", 
                    NIPQUAD(prefix), prefixlen);
            return -EROUTE_GW_UNREACHABLE;
        }
        /*check route entry is repeate*/
        help.next_hop = nexthop;
        li = __fib_find_leaf_info(t,
                                  key,
                                  prefixlen,
                                  PAL_ROUTE_COMMON,
                                  NEXTHOP_AM_LOOKUP,
                                  &help);
        if(li){
            PAL_ERROR("route exit "NIPQUAD_FMT"/%d \n", 
                    NIPQUAD(prefix), prefixlen);
            return -EROUTE_CIDR_EXIST;
        }
        vp = res.port_dev;
        connect_li = res.li;
    } else {
        if (vp->vport_type == PHY_VPORT) {
            /* QG shouldn't has nexthop, cause it connects to TOR directly. */
            if (nexthop != 0) {
                PAL_ERROR("add route, external port can't specify nexthop \n");
                return -EROUTE_GW_UNABLE_PHYPORT;
            }
            /* QG's connected route is default route */
            vport_prefix = 0;
            vport_prefixlen = 0;
        } else {
            vport_prefix = ip_to_prefix(vp->vport_ip, vp->prefix_len);
            vport_prefixlen = vp->prefix_len;
            /*Check nexthop is reachable.*/
            if (nexthop != 0) {
                vxlan_port = (struct int_vport *)vp;
                /* If nexthop is not in connected subnet of vport, or nexthop has no arp entry. */
                if (vport_prefix != ip_to_prefix(nexthop, vp->prefix_len)
                        || !find_vxlan_arp_entry(vxlan_port->vdev, nexthop)) {
                    PAL_ERROR("net unreachable for route "NIPQUAD_FMT"/%d \n", 
                        NIPQUAD(prefix), prefixlen);
                    return -EROUTE_GW_UNREACHABLE;
                }
            }
        }
        /* Since priority isn't implemented, same route item would be confusing. So ban it. */
        li = __fib_find_leaf_info(t,
                                  key,
                                  prefixlen,
                                  PAL_ROUTE_COMMON|PAL_ROUTE_LOCAL|PAL_ROUTE_CONNECTED,
                                  LPM_LOOKUP,
                                  NULL);
        if(li){
            PAL_ERROR("route exit "NIPQUAD_FMT"/%d \n", NIPQUAD(prefix), prefixlen);
            return -EROUTE_CIDR_EXIST;
        }
        help.sip = vp->vport_ip;
        connect_key = pal_ntohl(vport_prefix);
        connect_li = __fib_find_leaf_info(t,
                                          connect_key,
                                          vport_prefixlen,
                                          PAL_ROUTE_CONNECTED,
                                          SIP_AM_LOOKUP,
                                          &help);
    }
	if(!connect_li) {
		PAL_ERROR("BUG!\n");
        return -EROUTE_ERROR;
    }

	li = fib_insert_node(&t->trie, key, prefixlen);
	if (!li) {
		PAL_ERROR("fib insert node failed\n");
		return -EROUTE_ERROR;
	}
	li->prefix = prefix;
	li->next_hop = nexthop;	
	li->port_dev = vp;
	li->type = PAL_ROUTE_COMMON;
	li->sip = 0;
	add_leaf_info_to_connect(li,connect_li);
	t->route_entry_count++;

	return 0;
}


/* Add a static route with only nexthop. Just keep this old func to avoid trouble. */
int pal_route_add(struct route_table *t,
                  uint32_t prefix, 
                  uint32_t prefixlen,
                  uint32_t nexthop) {
    return _pal_route_add(t, prefix, prefixlen, nexthop, NULL);
}


/* Add a static route item to net */
int pal_route_add_to_net(void *net,
                         uint32_t prefix,
                         uint32_t prefixlen,
                         uint32_t nexthop,
                         char *vport_name) {
    struct route_table *t = NULL;
    t = get_nd_router_table(net);
    return route_add_static(t, prefix, prefixlen, nexthop, vport_name);
}

int pal_route_del_from_net(void *net,
                           uint32_t prefix,
                           uint32_t prefixlen) {
    struct route_table *t = NULL;
    t = get_nd_router_table(net);
    return pal_route_del(t, prefix, prefixlen);
}
/* Add a static route with nexthop and to_vport.
 * Lock of vport_net will be held. */
int route_add_static(struct route_table *t,
                     uint32_t prefix,
                     uint32_t prefixlen,
                     uint32_t nexthop,
                     char *vport_name) {
    uint32_t err;
	struct vport *to_vport = NULL;
	struct vport_net *vpnet = &vport_nets;

	if(strlen(vport_name) > VPORT_NAME_MAX) {
		return -ENXIO;
    }
    /* TODO: Lock to keep vport existing during route item adding.
     *       Here all vport and route operations would be locked.
     *       Lock of every vport maybe more reasonable. */
    pal_spinlock_lock(&vpnet->hash_lock);
    if (vport_name != NULL) {
        to_vport = __find_vport_nolock(vport_name);
        if (!to_vport) {
            pal_spinlock_unlock(&vpnet->hash_lock);
            return -ENXIO;
        }
    }
    err = _pal_route_add(t, prefix, prefixlen, nexthop, to_vport);
    pal_spinlock_unlock(&vpnet->hash_lock);

    return err;
}

int route_add_connected(struct route_table *t, uint32_t prefix, uint32_t prefixlen, 
				uint32_t sip,struct vport *vp)
{
	struct leaf_info *li;
	uint32_t key, mask;
	struct look_up_helper help;

	if (prefixlen > 32)
		return -1;

	key = pal_ntohl(prefix);
	mask = pal_ntohl(inet_make_mask(prefixlen));
	if (key & ~mask)
		return -1;

	if ((pal_ntohl(sip) & mask) != key) {
		PAL_DEBUG("sip & mask != prefix\n");
		return -1;
	}

	/*check route entry is repeate*/
	help.sip = sip;
	li = __fib_find_leaf_info(t,key,prefixlen,PAL_ROUTE_CONNECTED,SIP_AM_LOOKUP,&help);
	if(li){
		PAL_DEBUG("route exit "NIPQUAD_FMT"/%d ", 
				NIPQUAD(prefix), prefixlen);
		return -1;
	}

	li = fib_insert_node(&t->trie, key, prefixlen);
	if (li == NULL) {
		return -1;
	}
	
	li->prefix = prefix;
	li->next_hop = 0;	
	li->port_dev = vp;
	li->type = PAL_ROUTE_CONNECTED;
	li->sip = sip;
	PAL_INIT_LIST_HEAD(&li->route_list_head);

	t->route_entry_count++;

	return 0;
}

int route_add_local(struct route_table *t, uint32_t sip,struct vport *vp)
{
	struct leaf_info *li;
	uint32_t prefix;
	uint32_t prefixlen = LOCAL_TYPE_PRELEN;
	uint32_t key, mask;
	struct look_up_helper help;

	prefix = sip;
	key = pal_ntohl(prefix);
	mask = pal_ntohl(inet_make_mask(prefixlen));
	if (key & ~mask)
		return -1;

	if ((pal_ntohl(sip) & mask) != key) {
		PAL_DEBUG("sip & mask != prefix\n");
		return -1;
	}

	/*check route entry is repeate*/
	help.sip = sip;
	li = __fib_find_leaf_info(t,key,prefixlen,PAL_ROUTE_LOCAL,SIP_AM_LOOKUP,&help);
	if(li){
		PAL_DEBUG("route exit "NIPQUAD_FMT"/%d ", 
				NIPQUAD(prefix), prefixlen);
		return -1;
	}

	li = fib_insert_node(&t->trie, key, prefixlen);
	if (li == NULL) {
		return -1;
	}
	
	li->prefix = prefix;
	li->next_hop = 0;	
	li->port_dev = vp;
	li->type = PAL_ROUTE_LOCAL;
	li->sip = sip;

	t->route_entry_count++;
	return 0;
}

int pal_route_del(struct route_table * t,uint32_t prefix,uint32_t prefix_len)
{
	return __pal_route_del(t,prefix,prefix_len,PAL_ROUTE_COMMON,LPM_LOOKUP,NULL);
}

int pal_route_del_connect(struct route_table * t,uint32_t prefix,uint32_t prefix_len,uint32_t sip)
{
	struct look_up_helper help;
	help.sip = sip;
	return __pal_route_del(t,prefix,prefix_len,PAL_ROUTE_CONNECTED,SIP_AM_LOOKUP,&help);
}

int pal_route_del_local(struct route_table * t,uint32_t sip)
{
	struct look_up_helper help;
	help.sip = sip;
	return __pal_route_del(t,sip,LOCAL_TYPE_PRELEN,PAL_ROUTE_LOCAL,SIP_AM_LOOKUP,&help);
}

static void dump_route_entry(const struct rt_trie_node *n, __unused int level, void *reb)
{
	uint32_t mask;
	const struct leaf *l;
	const struct pal_hlist_node *hnode;
	const struct leaf_info *li;
	struct route_entry_table *rb = reb;

	if (IS_LEAF(n)) {
		l = (const struct leaf *)n;
		mask = pal_htonl(l->node.key);
		pal_hlist_for_each_entry_constant (li, hnode, &l->list, hlist) {

			if(rb->len >= MAX_ROUTE_ENTRY_NUM)
				return;

			rb->r_table[rb->len].prefix = li->prefix;
			rb->r_table[rb->len].prefixlen= li->plen;
			rb->r_table[rb->len].next_hop= li->next_hop;
			rb->r_table[rb->len].route_type= li->type;
			rb->r_table[rb->len].dev= li->port_dev;
			rb->len ++;
		}
	} 
}

void pal_trie_traverse(struct route_table *rtable,struct route_entry_table *reb)
{
	traverse_trie(rtable->trie,reb,dump_route_entry);
}

void route_slab_init(int numa_id)
{
	route_table_slab = pal_slab_create("route_table", ROUTE_TABLE_SLAB_SIZE, 
		 sizeof(struct route_table), numa_id, 0);
	 
	 if (!route_table_slab) {
		 PAL_PANIC("create route_table slab failed\n");
	 }

	leaf_info_slab = pal_slab_create("leaf_info", LEAF_INFO_SLAB_SIZE, 
		 sizeof(struct leaf_info), numa_id, 0);
	 
	 if (!leaf_info_slab) {
		 PAL_PANIC("create leaf info slab failed\n");
	 }

	leaf_slab = pal_slab_create("leaf", LEAF_SLAB_SIZE, 
		 max(sizeof(struct leaf), sizeof(struct leaf_info)), numa_id, 0);
	 
	 if (!leaf_slab) {
		 PAL_PANIC("create leaf slab failed\n");
	 }
}

