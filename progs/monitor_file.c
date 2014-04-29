#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/inotify.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )


int main(int argc, char *argv[])
{
  int length, i = 0;
  int fd;
  int wd;

  char *input_file;
 
  if(argc < 2) {
      printf("Usage : %s <file path to monitor>\n", argv[0]);
      exit(1);
  }    

  input_file = argv[1];

  char buffer[EVENT_BUF_LEN];

  fd = inotify_init();

  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  wd = inotify_add_watch( fd, input_file, IN_ALL_EVENTS );

  while (1) {    

      lseek( fd, 0, SEEK_SET ); 
      length = read( fd, buffer, EVENT_BUF_LEN );
      
      if ( length < 0 ) {
          perror( "read" );
      }

      struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];     if ( event->len ) {
      switch (event->mask &
          (IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED))
      {
      /* File was accessed */
          case IN_ACCESS:
                printf ("ACCESS: File %s is accessed.\n",event->name );
                break;

      /* File was modified */
         case IN_MODIFY:
                printf ("MODIFY: File %s is modified.\n",event->name );
                break;

      /* File changed attributes */
         case IN_ATTRIB:
                printf ("ATTRIB: Attribute changed for file %s.\n", event->name );
                break;

      /* File open for writing was closed */
         case IN_CLOSE_WRITE:
                printf ("CLOSE_WRITE: Opened File %s is closed.\n", event->name );
                break;

      /* File open read-only was closed */
         case IN_CLOSE_NOWRITE:
                printf ("CLOSE_NOWRITE: ReadOnly File %s is closed.\n ", event->name );
                break;

      /* File was opened */
         case IN_OPEN:
               printf ("OPEN: File %s is opened.\n", event->name );
               break;

         case IN_CREATE:
       	       if ( event->mask & IN_ISDIR ) {
	          printf( "New directory %s created.\n", event->name );
               }
               else {
                  printf( "New file %s created.\n", event->name );
               }
               break;

	 case IN_DELETE:
               if ( event->mask & IN_ISDIR ) {
                  printf( "Directory %s deleted.\n", event->name );
               }
               else {
                  printf( "File %s deleted.\n", event->name );
               }
               break;
      }

    }
  }
   inotify_rm_watch( fd, wd );

   close( fd );
}
