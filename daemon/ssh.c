#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ssh.h"

int verify_knownhost(ssh_session session)
{
  int state, hlen;
  unsigned char *hash = NULL;
  char *hexa;
  char buf[10];

  state = ssh_is_server_known(session);

  hlen = ssh_get_pubkey_hash(session, &hash);
  if (hlen < 0)
    return -1;

  switch (state)
    {
    case SSH_SERVER_KNOWN_OK:
      break; /* ok */

    case SSH_SERVER_KNOWN_CHANGED:
      fprintf(stderr, "Host key for server changed: it is now:\n");
      ssh_print_hexa("Public key hash", hash, hlen);
      fprintf(stderr, "For security reasons, connection will be stopped\n");
      free(hash);
      return -1;

    case SSH_SERVER_FOUND_OTHER:
      fprintf(stderr, "The host key for this server was not found but an other"
	      "type of key exists.\n");
      fprintf(stderr, "An attacker might change the default server key to"
	      "confuse your client into thinking the key does not exist\n");
      free(hash);
      return -1;

    case SSH_SERVER_FILE_NOT_FOUND:
      fprintf(stderr, "Could not find known host file.\n");
      fprintf(stderr, "If you accept the host key here, the file will be"
	      "automatically created.\n");
      /* fallback to SSH_SERVER_NOT_KNOWN behavior */

    case SSH_SERVER_NOT_KNOWN:
      hexa = ssh_get_hexa(hash, hlen);
      fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
      fprintf(stderr, "Public key hash: %s\n", hexa);
      free(hexa);
      if (fgets(buf, sizeof(buf), stdin) == NULL)
	{
	  free(hash);
	  return -1;
	}
      if (strncasecmp(buf, "yes", 3) != 0)
	{
	  free(hash);
	  return -1;
	}
      if (ssh_write_knownhost(session) < 0)
	{
	  fprintf(stderr, "Error %s\n", strerror(errno));
	  free(hash);
	  return -1;
	}
      break;

    case SSH_SERVER_ERROR:
      fprintf(stderr, "Error %s", ssh_get_error(session));
      free(hash);
      return -1;
    }

  free(hash);
  return 0;
}


ssh_session open_ssh_session(char* host, char* user, char* path) {
  int rc;
  char* password;
  // Open session and set options
  ssh_session session = ssh_new();
  if (session == NULL)
    exit(-1);
  ssh_options_set(session, SSH_OPTIONS_HOST, host);
  ssh_options_set(session, SSH_OPTIONS_SSH_DIR, path);

  // Connect to server
  rc = ssh_connect(session);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Error connecting to %s: %s\n",
	      host, ssh_get_error(session));
      ssh_free(session);
      exit(-1);;
    }

  // Verify the server's identity
  if (verify_knownhost(session) < 0)
    {
      ssh_disconnect(session);
      ssh_free(session);
      exit(-1);
    }

  // Authenticate ourselves
  password = getpass("Password: ");
  rc = ssh_userauth_password(session, user, password);
  if (rc != SSH_AUTH_SUCCESS)
    {
      fprintf(stderr, "Error authenticating with password: %s\n",
	      ssh_get_error(session));
      ssh_disconnect(session);
      ssh_free(session);
      exit(-1);
    }
  
  return session;
}


void close_session(ssh_session session) {
  ssh_disconnect(session);
  ssh_free(session);
}


int sftp_read_file(ssh_session session, char* filepath, loff_t* offset, int size, char* buffer) {
  sftp_session sftp;
  int rc, sum;

  // init
  sftp = sftp_new(session);
  if (sftp == NULL)
    {
      fprintf(stderr, "Error allocating SFTP session: %s\n",
	      ssh_get_error(session));
      return -EIO;
    }

  rc = sftp_init(sftp);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Error initializing SFTP session: %s.\n",
	      (char*) sftp_get_error(sftp));
      sftp_free(sftp);
      return -EIO;
    }

  // read
  sum = sftp_read_sync(session, sftp, filepath, offset, size, buffer);
  
  // closing

  sftp_free(sftp);
  return sum;
}


int sftp_read_sync(ssh_session session, sftp_session sftp, char* filepath, loff_t* offset, int size, char* buffer)
{
  int access_type;
  sftp_file file;
  int nbytes, rc;

  access_type = O_RDONLY;
  file = sftp_open(sftp, filepath,
                   access_type, 0);
  if (file == NULL)
    {
      fprintf(stderr, "Can't open file for reading: %s\n",
	      ssh_get_error(session));
      return -EIO;
    }

  if (sftp_seek(file, *offset) < 0)
    {
      fprintf(stderr, "Can't seek file: %s\n",
	      ssh_get_error(session));
      return -EIO;
    
    }

  nbytes = sftp_read(file, buffer, size);

  if (nbytes < 0)
    {
      fprintf(stderr, "Error while reading file: %s\n",
	      ssh_get_error(session));
    }

  *offset = sftp_tell(file);

  rc = sftp_close(file);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Can't close the read file: %s\n",
	      ssh_get_error(session));
      return -EIO;
    }

  return nbytes;
}


int sftp_write_file(ssh_session session, char* filepath, loff_t* offset, char* msg, int size) {
  sftp_session sftp;
  int rc;

  // init
  sftp = sftp_new(session);
  if (sftp == NULL)
    {
      fprintf(stderr, "Error allocating SFTP session: %s\n",
	      ssh_get_error(session));
      return -EIO;
    }

  rc = sftp_init(sftp);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Error initializing SFTP session: %s.\n",
	      (char*) sftp_get_error(sftp));
      sftp_free(sftp);
      return -EIO;
    }

  // write
  rc = sftp_write_sync(session, sftp, filepath, offset, msg, size);
  
  // closing
  sftp_free(sftp);
  return rc;
}


int sftp_write_sync(ssh_session session, sftp_session sftp, char* filepath, loff_t* offset, char* msg, int size)
{
  int access_type = O_WRONLY;
  sftp_file file;
  int rc, nwritten;

  file = sftp_open(sftp, filepath,
		   access_type, S_IRWXU);
  if (file == NULL)
    {
      fprintf(stderr, "Can't open file for writing: %s\n",
	      ssh_get_error(session));
      return -EIO;
    }

  if (sftp_seek(file, *offset) < 0)
    {
      fprintf(stderr, "Can't seek file: %s\n",
	      ssh_get_error(session));
      return -EIO;
    
    }
  
  nwritten = sftp_write(file, msg, size);
  if (nwritten != size)
    {
      fprintf(stderr, "Can't write data to file: %s\n",
	      ssh_get_error(session));
    }

  *offset = sftp_tell(file);

  rc = sftp_close(file);
  if (rc != SSH_OK)
    {
      fprintf(stderr, "Can't close the written file: %s\n",
	      ssh_get_error(session));
    }

  return nwritten;
}

int sftp_list_dir(ssh_session session, char* dirpath, char* buf) {
  sftp_session sftp;
  sftp_dir dir;
  sftp_attributes attrs;
  char* ptr = buf;
  int rc, sum;

  // init
  sftp = sftp_new(session);
  if (sftp == NULL)
	{
	  fprintf(stderr, "Error allocating SFTP session: %s\n",
		  ssh_get_error(session));
	  return -1;
	}

  rc = sftp_init(sftp);
  if (rc != SSH_OK)
	{
	  fprintf(stderr, "Error initializing SFTP session: %s.\n",
		  (char*) sftp_get_error(sftp));
	  sftp_free(sftp);
	  return -1;
	}

  dir = sftp_opendir(sftp, dirpath);
  if(dir == NULL)
  	{
	  fprintf(stderr, "Error opening directory: %s.\n",
		  (char*) sftp_get_error(sftp));
	  sftp_free(sftp);
	  return -1;
    }

  while(1) {
	  attrs = sftp_readdir(sftp, dir);
	  if(attrs == NULL) {
		  break;
	  }
	  if(attrs->type == SSH_FILEXFER_TYPE_REGULAR) {
		  strcpy(ptr, attrs->name);
		  ptr += strlen(ptr)+1;
	  }
  }

  sftp_free(sftp);

  return ptr-buf;
}

/*
int main()
{
  // test funkcji
  ssh_session my_ssh_session;
  char* user = "schiza";
  char* host = "localhost";
  char* filepath = "/home/schiza/Pulpit/test-ssh.txt";
  char* msg = "i kot jest zdrowy!\n";
  int offset = 12;
  int size = 19;
  
  // init 
  my_ssh_session = open_ssh_session(host, user);
  printf("Authentication succeeded!\n");
  printf("Connection to %s@%s established\n", user, host);

  // testy read i write
  sftp_read_file(my_ssh_session, filepath, offset, size);
  //sftp_write_file(my_ssh_session, filepath, offset, msg);

  // close
  close_session(my_ssh_session);
  printf("Connection to %s@%s closed\n", user, host);
}
*/
