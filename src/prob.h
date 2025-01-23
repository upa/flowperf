/* prob.h */

#ifndef _PROB_H_
#define _PROB_H_

#include <stdlib.h>

#define PROB_KEY_SIZE	64

struct prob_struct {
	double	prob;
	void	*data;
	char	key[PROB_KEY_SIZE];
};
typedef struct prob_struct prob_t;

struct prob_list_struct {
	size_t	size;		/* probs size */
	prob_t	*probs;	/* probs[size].prob is -1 (sentinel) */
};
typedef struct prob_list_struct prob_list_t;


/**
 * parse prob text and returns prob_list, prob_t.data is the key on each line.
 */
prob_list_t *parse_prob_text(const char *path);

/**
 * list:   prob_list_t*
 * prob:   prob_t* where the next prob is stored
 */
#define foreach_prob(list, prob)			\
	for (prob = &list->probs[0]; prob->prob > 0; prob++)


/**
 * pickup a prob object from the list. needle is a decimal on [0.0, 1.0].
 */
prob_t *pickup_prob(prob_list_t *list, double needle);

#define pickup_prob_uniformly(list) pickup_prob(list, (double)rand() / RAND_MAX)

#endif /* _PROB_H_ */
