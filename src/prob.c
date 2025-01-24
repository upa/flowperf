

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include <prob.h>
#include <print.h>

prob_list_t *prob_list_alloc(void)
{
	prob_list_t *list;
	
	if ((list = malloc(sizeof(*list))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return NULL;
	}
	memset(list, 0, sizeof(*list));

	list->size = 0;
	list->probs = realloc(list->probs, 1 * sizeof(prob_t));
	list->probs[0].probability = -1;	/* sentinel */

	return list;
}

int prob_list_append(prob_list_t *list, double prob_value, const char *key)
{
	prob_t *prob;

	if (prob_value < 0) {
		pr_err("probability must be greater or equal to 0: %s %f",
		       key, prob_value);
		return -1;
	}

	list->probs = realloc(list->probs, (list->size + 1) * sizeof(prob_t));
	if (!list->probs) {
		pr_err("realloc: %s", strerror(errno));
		return -1;
	}

	prob = &list->probs[list->size];
	prob->probability = prob_value;
	prob->data = NULL;
	strncpy(prob->key, key, PROB_KEY_SIZE);
	
	list->probs[++list->size].probability = -1; /* sentinel */
	return 0;
}

int prob_list_load_text(prob_list_t *list, const char *path)
{
	char buf[512], key[256];
	double prob_value;
	FILE *f;
	int ret;

	if ((f = fopen(path, "r")) == NULL) {
		pr_err("fopen(%s): %s", path, strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[0] == '#') continue;
		ret = sscanf(buf, "%s %lf", key, &prob_value);
		if (ret == 2) {
			if (strlen(key) > PROB_KEY_SIZE)
				pr_warn("too long key \"%s\", truncated", key);

			if (prob_list_append(list, prob_value, key) < 0)
				return -1;
		}
	}

	fclose(f);

	return 0;
}

void prob_list_convert_to_cdf(prob_list_t *list)
{
	double prob_total = 0, prob_cum = 0;
	prob_t *prob;

	/* change list->probs[].prob as cumulative ones */

	foreach_prob(list, prob)
		prob_total += prob->probability;

	foreach_prob(list, prob) {
		prob_cum += prob->probability;
		prob->probability = prob_cum / prob_total;
	}
}


int prob_list_iterate(prob_list_t *list, int (*iter)(prob_t *))
{
	prob_t *prob;

	/* apply iter to all prob in the list */
	foreach_prob(list, prob) {
		if (iter(prob) < 0) {
			pr_err("iter function failed: key=%s probability=%f",
			       prob->key, prob->probability);
			return -1;
		}
	}
	return 0;
}

prob_t *pickup_prob(prob_list_t *list, double needle)
{
	int i = round(list->size / 2);
	prob_t *prob;

	assert(list->size > 0);

	while (1) {
		/* bidirectional search */
		prob = &list->probs[i];
		if (prob->probability >= needle &&
		    (i == 0 || needle > list->probs[i-1].probability)) {
			return prob;
		}

		if (prob->probability > needle)
			i += round((list->size - i) / 2);
		else
			i -= round(i / 2);
	}
}

void prob_list_dump_debug(prob_list_t *list)
{
	prob_t *prob;
	if (get_print_severity() >= SEVERITY_DEBUG) {
		foreach_prob(list, prob) {
			pr_debug("%s\t%f", prob->key, prob->probability);
		}
	}
}
