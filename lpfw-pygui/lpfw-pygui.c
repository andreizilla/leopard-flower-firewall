#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <grp.h>
#include "../common/defines.h"
#include "../common/includes.h"
#include "../argtable/argtable2.h"
#include "../version.h"

struct arg_file *python_folder;
struct arg_int *log_debug;


void check_own_gid()
{
    gid_t lpfwuser_gid, own_gid;
    struct group *m_group;

    errno = 0;
    m_group = getgrnam("lpfwuser");
    if(!m_group)
      {
	if (errno == 0)
	  {
	    printf ("lpfwuser group still doesn't exist even though we've just created it \n");
	  }
	else
	  {
	    perror ("getgrnam");
	  }
      }
    lpfwuser_gid = m_group->gr_gid;
    own_gid = getegid();
    if (own_gid != lpfwuser_gid)
    {
	printf("Please set gid to lpfwuser on this file, current gid:%d ,need to set to: %d\n", (int)own_gid, (int)lpfwuser_gid);
	exit(0);
    }
}

void parse_command_line(int argc, char* argv[])
{
    // if the parsing of the arguments was unsuccessful
    int nerrors;

    // Define argument table structs
    python_folder = arg_file0 ( NULL, "py-folder", "<path to file>", "Path to folder (relative or absolute) that contains python script (default: lpfw-pygui" );
    log_debug = arg_int0 ( NULL, "log-debug", "<1/0 for yes/no>", "Enable debug messages logging" );

    struct arg_lit *help = arg_lit0 ( NULL, "help", "Display this help screen" );
    struct arg_lit *version = arg_lit0 ( NULL, "version", "Display the current version" );
    struct arg_end *end = arg_end ( 10 );
    void *argtable[] = {python_folder, log_debug, help, version, end};

    // Set default values
    char *python_folder_pointer = malloc(strlen("lpfw-pygui")+1);
    strcpy (python_folder_pointer, "lpfw-pygui");
    python_folder->filename[0] = python_folder_pointer;

    * ( log_debug->ival ) = 0;

    if ( arg_nullcheck ( argtable ) != 0 )
      {
	printf ( "Error: insufficient memory\n" );
	exit(0);
      }

    nerrors = arg_parse ( argc, argv, argtable );

    if ( nerrors == 0 )
      {
	if ( help->count == 1 )
	  {
	    printf ( "Leopard Flower frontend :\n Syntax and help:\n" );
	    arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
	    exit (0);
	  }
	else if ( version->count == 1 )
	  {
	    printf ( "%s\n", VERSION );
	    exit (0);
	  }
    }
    else if ( nerrors > 0 )
      {
	arg_print_errors ( stdout, end, "Leopard Flower frontend" );
	printf ( "Leopard Flower frontend:\n Syntax and help:\n" );
	arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
	exit (1);
      }

    // Free memory - don't do this cause args needed later on
    //  arg_freetable(argtable, sizeof (argtable) / sizeof (argtable[0]));
}



int main (int argc, char* argv[])
{
    check_own_gid();
    parse_command_line(argc, argv);
    char system_call_string[PATHSIZE];
    strcpy(system_call_string, "python ");
    strncat(system_call_string, python_folder->filename[0], PATHSIZE-10);
    strcat(system_call_string, "/lpfwgui.py");
    system(system_call_string );
	
}
