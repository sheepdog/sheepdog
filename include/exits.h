#ifndef __EXITS_H__
#define __EXITS_H__

#define EXIT_SUCCESS 0 /* command executed successfully */
#define EXIT_FAILURE 1 /* command failed to execute */
#define EXIT_SYSFAIL 2 /* something is wrong with the cluster or local host */
#define EXIT_EXISTS  3 /* the object already exists so cannot be created */
#define EXIT_FULL    4 /* no more space is left in the cluster */
#define EXIT_MISSING 5 /* the specified object does not exist */
#define EXIT_USAGE  64 /* invalid command, arguments or options */

#endif
