# totp
totp is a a CLI TOTP tool that aims to mimics Google Authenticator. For usage,
see the man page, or read the scdoc source in `totp.1.scd`. totp also uses
[colors.h](https://github.com/michaelfm1211/colors.h) to make stuff look good.

#### Extras
- [MAC ONLY] To get a top bar icon next to your wifi, control center, etc.,
you can use [xbar](https://github.com/matryer/xbar) and
[these nifty scripts](https://gist.github.com/michaelfm1211/32336940e1d27c4b2a44c9e3f665f26c)

If you make something useful/cool with totp, make a pull request to advertise
it here.

### Building
totp depends on openssl. If you want to build the man page too, you will need
[scdoc](https://sr.ht/~sircmpwn/scdoc/). Just run `make` or `make install` to
compile or compile and install the program.

### Warning
totp stores your secret keys in plaintext. In the future this will probably
change and it become encrypted by default, but for now it is not. If you're
paranoid, you can probably write a simple script to decrypt your
totp_secrets file (read the man page for more info), run totp, then encrypt
the file again. Unless you're managing other people's keys or are being
watched/hacked, you're probably OK.
