/* prob.h */

#ifndef _PROB_H_
#define _PROB_H_

#include <stdlib.h>

#define PROB_KEY_SIZE	64

struct prob_struct {
	double	probability;
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
 * list:   prob_list_t*
 * prob:   prob_t* where the next prob is stored
 */
#define foreach_prob(list, prob)                       \
       for (prob = &list->probs[0]; prob->probability > 0; prob++)


/* allocate a new prob_list_t */
prob_list_t *prob_list_alloc(void);

/* add a new prob_t to the list */
int prob_list_append(prob_list_t *list, double prob_value, const char *key);

/* parse prob text and append prob_t to the list */
int prob_list_load_text(prob_list_t *list, const char *path);

/* convert independent probability to cumulative ones */
void prob_list_convert_to_cdf(prob_list_t *list);



/*
 * pickup a prob object from the list. needle is a decimal on [0.0, 1.0].
 */
prob_t *prob_list_pickup(prob_list_t *list, double needle);

#define prob_list_pickup_uniformly(list) pickup_prob(list, (double)rand() / RAND_MAX)

void prob_list_dump_debug(prob_list_t *list);

#endif /* _PROB_H_ */
