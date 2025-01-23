
#include <stdio.h>
#include <string.h>

#include <prob.h>
#include <print.h>

prob_list_t *prase_prob_text(const char *path)
{
	prob_list_t *list;
	prob_t *prob;
	char buf[512], key[256];
	double prob_value, total, cum;
	FILE *f;
	int i = 0;

	if ((list = malloc(sizeof(*list))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return NULL;
	}
	list->size = 0;

	if ((f = fopen(path, "r")) == NULL) {
		pr_err("fopen(%s): %s", path, strerror(errno));
		return NULL;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[0] == '#') continue;
		if (sscanf("%s %f", key, &prob_value) == 2) {
			if (strlen(key) > PROB_KEY_SIZE)
				pr_warn("too long key \"%s\", truncated", key);

			list->probs = realloc(list->probs, i * sizeof(prob_t));
			if (list->probs == NULL) {
				pr_err("realloc: %s", strerror(errno));
				return NULL;
			}
			list->probs[i].prob = prob_value;
			list->probs[i].data = NULL;
			strncpy(list->probs[i].key, key, PROB_KEY_SIZE);
			i++;
		}
	}

	list->size = i;

	/* add sentinel */
	list->probs = realloc(list->probs, i * sizeof(prob_t));
	if (list->probs == NULL) {
		pr_err("realloc: %s", strerror(errno));
		return NULL;
	}
	list->probs[i].prob = -1;
	list->probs[i].data = NULL;
	strncpy(list->probs[i].key, "sentinel", PROB_KEY_SIZE);

	fclose(f);

	/* change list->probs[].prob as cumulative ones */
	total = 0;
	foreach_prob(list, prob) {
		total += prob->prob;
	}

	cum = 0;
	foreach_prob(list, prob) {
		cum += prob->prob;
		prob->prob = cum / total;
	}

	return list;
}
