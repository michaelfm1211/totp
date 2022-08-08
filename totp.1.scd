TOTP(1)

# NAME

totp - Google Authenicator-like functionality from the command line

# SYNOPYSIS

*totp* [*-rlh*] [*-c* secrets_file] [*-a* service:secret] [*-d* service] [services...]

# DESCRIPTION

The *totp* program implements the TOTP protocol as described in RFC 6238. The
goal of this program is to mimic the Google Authenicator app as much as
possible, but on compatible the command line. If given no flags, *totp* will
calculate the TOTP values for each configured service in _services_. By
default, *totp* will format the output nicely and tell you how much time you
have left until the keys expire (use *-r* to disable this). If given options
*-l*, *-h*, *-a*, or *-d*, *totp* will not calculate the TOTP values for
_services_ and will exit with a status code instead. By default, *totp* stores 
all TOTP secret keys in $XDG_CONFIG_HOME/totp_secrets in plaintext. Make sure 
you do not share this file. In the future, this file will likely be encrypted 
by default as per RFC 6238 reccomendations.

# OPTIONS
*-r*
	Disable the default formatting when calculating the TOTP values for
	_services_. This can be useful for scripting or if you want to pipe
	the output into your clipboard (ex: totp -r google | pbcopy).
*-l*
	List all configured services, along with their secrets. Don't share
	the output of the command. Use this command if you want to move your 
	secrets to another program.
*-h*
	Print the usage of the program.
*-c* _secrets\_file_
	Use a different file as your secrets file. totp will use 
	_secrets\_file_ instead of your default totp_secrets file. totp will 
	ensure that this file is valid before reading it by checking that the
	file starts with a magic line. The magic line should be "DO NOT DELETE
	THIS LINE" followed by a new line character (0x0a).
*-a* _service_:_secret_
	Add/configure a new service that *totp* will keep track of. _service_
	will be the name you interact with when you ask *totp* to generate the
	TOTP value for it. _secret_ is the secret key that your account
	provider gave you when configuring TOTP authentication. *totp* does
	not check if this service has already been configured, so if you're
	unsure, double check with the *-l* option. If you mess up, you can
	delete the service with the *-d* option and run the *-a* option again.
	If something goes really wrong, you might need to edit your 
	totp_secrets file (don't worry, its a straight-forward plaintext
	file).
*-d* _service_
	Deletes a configured service. This is pretty self-explanatory, just
	make sure you delete the service from *totp* after you disable TOTP
	authentication on your account.

# AUTHORS

*totp* was written by Michael M (https://github.com/michaelfm1211).
