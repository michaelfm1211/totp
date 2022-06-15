# totp
totp is a a CLI TOTP tool that aims to mimics Google Authenticator. For usage,
see the man page, or read the scdoc source in `totp.1.scd`. totp also uses
[colors.h](https://github.com/michaelfm1211/colors.h) to make stuff look good.

### Building
totp depends on openssl. If you want to build the man page too, you will need
[scdoc](https://sr.ht/~sircmpwn/scdoc/). Just run `make` or `make install` to
compileor compile and install the program.
