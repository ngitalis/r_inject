/*
**                     Dependency Injection Toolset
**                               (main.c) 
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <inject.h>

static void
usage(const char* progname, int retval)
{
    fprintf(stderr, "usage: %s <command> <pid> [arguments...]\n", progname);
    fprintf(stderr, "where <command> is one of:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " dlopen <pid> <library>\n");
    fprintf(stderr, "       Map a new shared object into the address space.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " remap <pid> <original-symbol> <new-symbol>\n");
    fprintf(stderr, "       Remap calls from the given symbol to a new symbol.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " call <pid> <symbol> <argument>\n");
    fprintf(stderr, "       Inject a one-off call to the given symbol.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "NOTE: A symbol can be specified as [library:]symbol, where library\n");
    fprintf(stderr, "will be used for a soft match on the object name in the process\n");
    fprintf(stderr, "address space.  If the library is not specified, then all libraries\n");
    fprintf(stderr, "will be searched.  For example, to replace calls to 'nanosleep' in\n");
    fprintf(stderr, "the program 'yes', we might use:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    %s dlopen <pid> /full/path/to/mylib.so\n", progname);
    fprintf(stderr, "    %s remap <pid> yes:nanosleep mylib:foo\n", progname);
    fprintf(stderr, "\n");
    exit(retval);
}

static int
get_symbol_info(const char* name, int pid, char** maps, char* forcelib, char* symbol, inject_info_t* info)
{
    int i = 0;
    
    /* Parse the original symbol. */
    char* origlib     = forcelib;
    char* origsymname = symbol;

    if( (origlib == NULL) && (strchr(origsymname, ':') != NULL) )
    {
        origlib = origsymname;
        origsymname = strchr(origsymname, ':');
        *origsymname = '\0';
        origsymname++;
    }

    fprintf(stderr, "\n%s symbol:\n", name);
    fprintf(stderr, "  Symbol = %s\n", origsymname);
    fprintf(stderr, "  Library = %s\n", origlib == NULL ? "..." : origlib);

    /* Grab the original symbol info (if no library was specified). */
    if( origlib == NULL )
    {
        int found = 0;
        for( i = 0; maps[i] != NULL; i++ )
        {
            if( inject_getaddr_info(pid, maps[i], origsymname, info) == 0 )
            {
                fprintf(stderr, "    %s\n", maps[i]);
                origlib = (char*)maps[i];
                found++;
            }
        }
        if( found > 1 )
        {
            fprintf(stderr, "Ambigious %s symbol %s (try specifying a library).\n", name, origsymname);
            return 1;
        }
        else if( found == 0 )
        {
            fprintf(stderr, "Oops -- %s symbol %s not found.\n", name, origsymname);
            return 1;
        }
    }
    else
    {
        if( inject_getaddr_info(pid, origlib, origsymname, info) != 0 )
        {
            fprintf(stderr, "Oops -- %s symbol %s not found in %s.\n", name, origsymname, origlib);
            return 1;
        }
	else if (forcelib == NULL)
        {
	    fprintf(stderr, "  Found: %s\n", info->map_path);
        }
    }

    return 0;
}

static int
do_dlopen(int pid, const char* library)
{
    if(inject_dlopen(pid, library) < 0) {
        fprintf(stderr, "Unable to map library: %s\n", strerror(errno));
    return 1;
    }

    return 0;
}

static void
free_maps(char** maps)
{
    int i = 0;
    for( i = 0; maps[i] != NULL; i++ )
    {
        free(maps[i]);
    }
    free(maps);
}

static int
do_call(int pid, char* symbol, const char* arg)
{
    inject_info_t target;

    /* Grab the maps. */
    char** maps = inject_get_maps(pid);

    if( get_symbol_info("Target", pid, maps, NULL, symbol, &target) < 0 ) {
        free_maps(maps);
        return 1;
    }

    /* Call the symbol. */
    if( inject_call(pid, &target, arg) < 0 ) {
        fprintf(stderr, "Call failed: %s\n", strerror(errno));
        free_maps(maps);
        return 1;
    }

    free_maps(maps);
    return 0;
}

static int
do_remap(int pid, char* origsym, char* newsym)
{
    int i = 0;

    /* Function info. */
    inject_info_t original;
    inject_info_t target;

    /* Grab the maps. */
    char** maps = inject_get_maps(pid);
    if( maps == NULL )
    {
        fprintf(stderr, "Unable to fetch maps for process %d!\n", pid);
        return 1;
    }

    /* Grab the target (fixed). */
    if( get_symbol_info("Target", pid, maps, NULL, newsym, &target) )
    {
        free_maps(maps);
        return 1;
    }

    if( strchr(origsym, ':') == NULL )
    {
        /* remap all */
        fprintf(stderr, "\nNo explicit path specified on original-symbol. Scanning....");
        for( i = 0; maps[i] != NULL; i++ )
        {
            if( get_symbol_info("Original", pid, maps, maps[i], origsym, &original) )
                continue;
            if( inject_remap(pid, &original, &target) != 0 )
            {
                fprintf(stderr, "Error remapping symbol in %s: %s.\n", maps[i], strerror(errno));
                /* Ignore in this case (some may be succesful). */
            }
	    else
	    {
	      fprintf(stderr, "Remapped Symbol: %s in %s.\n", origsym, maps[i]);
	    }
        }
    }
    else
    {
        if( get_symbol_info("Original", pid, maps, NULL, origsym, &original) )
        {
            free_maps(maps);
            return 1;
        }
        /* remap one */
        if( inject_remap(pid, &original, &target) != 0 )
        {
            fprintf(stderr, "Error remapping symbol in %s: %s.\n", original.map_path, strerror(errno));
            free_maps(maps);
            return 1;
        }
    }

    free_maps(maps);
    return 0;
}

int
main(int argc, char** argv)
{
    char* command = NULL, c;
    int pid;

    while ((c = getopt (argc, argv, "h")) != -1)
    switch (c)
    {
        case 'h':
        usage(argv[0], 0);
        default:
        usage(argv[0], 1);
    }

    /* Ensure at least command, PID. */
    if( (optind+1) >= argc )
        usage(argv[0], 1);

    /* Grab the command and PID. */
    command = argv[optind];
    pid = strtol(argv[optind + 1], NULL, 0);
    if( pid == 0 )
    {
        fprintf(stderr, "Invalid pid provided.\n");
        usage(argv[0], 1);
    }

    if( strcasecmp(command, "dlopen") == 0 )
    {
        if( (optind+2) >= argc )
            usage(argv[0], 1);
        return do_dlopen(pid, argv[optind+2]);
    }
    else if( strcasecmp(command, "remap") == 0 )
    {
        if( (optind+3) >= argc )
            usage(argv[0], 1);
        return do_remap(pid, argv[optind+2], argv[optind+3]);
    }
    else if( strcasecmp(command, "call") == 0 )
    {
        if( (optind+2) < argc )
            return do_call(pid, argv[optind+2], argv[optind+3]);
        else if( (optind+1) < argc )
            return do_call(pid, argv[optind+2], NULL);
        else
            usage(argv[0], 1);
    }
    else
    {
        usage(argv[0], 1);
    }

    return 0;
}
