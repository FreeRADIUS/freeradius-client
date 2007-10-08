/*
 * radembedded.c - a sample c program showing how to embed the configuration of a radius
 * client, using the FreeRADIUS Client Library without an external configuration file.
 */


#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <freeradius-client.h>


int
main (int argc, char **argv)
{
	int		retval = 0;
	rc_handle 	*rh = NULL;

	uint32_t 		client_port = 0;
	uint32_t		status_type = PW_STATUS_STOP; 
        VALUE_PAIR      *send = NULL;
/*
	VALUE_PAIR 	*vp = NULL;
	DICT_VALUE 	*dval = NULL;
*/
	char		username[255] = "bob@somedomain.here";
	char		callfrom[255] = "8475551212";
	char		callto[255] = "8479630116";
	char		myuuid[255] = "981743-asdf-90834klj234";

	/* Initialize the 'rh' structure */

	rh = rc_new();
	if (rh == NULL) 
	{
		printf("ERROR: Failed to allocate initial structure\n");
		exit(1);
	}

	/* Initialize the config structure */

	rh = rc_config_init(rh);
	if (rh == NULL)
	{
		printf("ERROR: Failed to initialze configuration\n");
		exit(1);
	}

	/* 
	 * Set the required options for configuration
	 */

	/* set auth_order to be radius only */

	if (rc_add_config(rh, "auth_order", "radius", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set auth_order.\n");
		rc_destroy(rh);
		exit(1);
	}

	if (rc_add_config(rh, "login_tries", "4", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set login_tries.\n");
		rc_destroy(rh);
		exit(1);
	}

	if (rc_add_config(rh, "dictionary", "/usr/local/radius/dictionary", "config", 0) != 0)
	{
		printf("ERROR: Unable to set dictionary.\n");
		rc_destroy(rh);
		exit(1);
	}
	
	if (rc_add_config(rh, "seqfile", "/var/run/radius.seq", "config", 0) != 0)
	{
		printf("ERROR: Unable to set seq file.\n");
		rc_destroy(rh);
		exit(1);
	}
	
	if (rc_add_config(rh, "radius_retries", "3", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set radius_retries.\n");
		rc_destroy(rh);
		exit(1);
	}

	if (rc_add_config(rh, "radius_timeout", "5", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set radius_timeout.\n");
		rc_destroy(rh);
		exit(1);
	}

	/* auth/acct servers are added in the form: host[:port[:secret]]
	 * If you don't set the secret via the add_config option, you must set a 'servers'
         * entry to specify the location of the 'servers' file which stores the secrets to
         * be used.
         */

	if (rc_add_config(rh, "authserver", "localhost::testing123", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set authserver.\n");
		rc_destroy(rh);
		exit(1);
	}

	if (rc_add_config(rh, "acctserver", "localhost:1813:testing123", "config", 0) != 0) 
	{
		printf("ERROR: Unable to set acctserver.\n");
		rc_destroy(rh);
		exit(1);
	}

	/* Done setting configuration items */
	
	/* Read in the dictionary file(s) */

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) 
	{
		printf("ERROR: Failed to initialize radius dictionary\n");
		exit(1);
	}

        if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL)
	{	
		printf("ERROR: Failed adding Acct-Status-Type: to %d\n", status_type);		
                exit(1);
	}
        if (rc_avpair_add(rh, &send, PW_ACCT_SESSION_ID, myuuid, -1, 0) == NULL)
	{	
		printf("ERROR: Failed adding Acct-Session-ID: to %s\n", myuuid);		
                exit(1);
	}
        if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL)
	{	
		printf("ERROR: Failed adding User-Name: to %s\n", username);		
                exit(1);
	}
        if (rc_avpair_add(rh, &send, PW_CALLED_STATION_ID, callto, -1, 0) == NULL)
	{	
		printf("ERROR: Failed adding Called-Station-ID: to %s\n", callto);		
                exit(1);
	}
        if (rc_avpair_add(rh, &send, PW_CALLING_STATION_ID, callfrom, -1, 0) == NULL)
	{	
		printf("ERROR: Failed adding Calling-Station-ID: to %s\n", callfrom);		
                exit(1);
	}

	if(rc_acct(rh, client_port, send) == OK_RC)
	{
		printf("INFO: Accounting OK: %s\n", username);
		retval = 0;
	}
	else
	{
		printf("INFO: Accounting Failed: %s\n", username);
		retval = -1;
	}
	rc_destroy(rh);
	rc_avpair_free(send);

	exit(retval);
}
