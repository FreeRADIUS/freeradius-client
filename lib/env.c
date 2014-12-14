/*
 * $Id: env.c,v 1.6 2007/06/21 18:07:23 cparker Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>

/**
 * rc_new_env:
 * @size: the maximum size of the environment
 *
 * Allocate space for a new environment
 *
 * Returns: the initialized environment
 **/

ENV *rc_new_env(int size)
{
	ENV *p;

	if (size < 1)
		return NULL;

	if ((p = malloc(sizeof(*p))) == NULL)
		return NULL;

	if ((p->env = malloc(size * sizeof(char *))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_new_env: out of memory");
		free(p);
		return NULL;
	}

	p->env[0] = NULL;

	p->size = 0;
	p->maxsize = size;

	return p;
}

/**
 * rc_free_env:
 * @env: an initialized environment value 
 *
 * free the space used by an env structure
 *
 **/

void rc_free_env(ENV *env)
{
	free(env->env);
	free(env);
}

/**
 * rc_add_env:
 * @env: an initialized environment value 
 *
 * add an environment entry
 *
 * Returns: 0 on success or -1 on error
 **/

int rc_add_env(ENV *env, char const *name, char const *value)
{
	int i;
	size_t len;
	char *new_env;

	for (i = 0; env->env[i] != NULL; i++)
	{
		if (strncmp(env->env[i], name, MAX(strchr(env->env[i], '=') - env->env[i], (int)strlen(name))) == 0)
			break;
	}

	if (env->env[i])
	{
		len = strlen(name)+strlen(value)+2;
		if ((new_env = realloc(env->env[i], len)) == NULL)
			return -1;

		env->env[i] = new_env;

		snprintf(env->env[i], len, "%s=%s", name, value);
	} else {
		if (env->size == (env->maxsize-1)) {
			rc_log(LOG_CRIT, "rc_add_env: not enough space for environment (increase ENV_SIZE)");
			return -1;
		}

		len = strlen(name)+strlen(value)+2;
		if ((env->env[env->size] = malloc(len)) == NULL) {
			rc_log(LOG_CRIT, "rc_add_env: out of memory");
			return -1;
		}

		snprintf(env->env[env->size], len, "%s=%s", name, value);

		env->size++;

		env->env[env->size] = NULL;
	}

	return 0;
}

/**
 * rc_import_env:
 * @env: an initialized environment value 
 *
 * imports an array of null-terminated strings
 *
 * Returns: 0 on success or -1 on error
 **/

int rc_import_env(ENV *env, char const **import)
{
	char *es;

	while (*import)
	{
		es = strchr(*import, '=');

		if (!es)
		{
			import++;
			continue;
		}

		/* ok, i grant thats not very clean... */
		*es = '\0';

		if (rc_add_env(env, *import, es+1) < 0)
		{
			*es = '=';
			return -1;
		}

		*es = '=';

		import++;
	}

	return 0;
}
