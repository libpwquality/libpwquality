libpwquality NEWS -- history of user-visible changes.

Release 1.4.4
* Fix regression with enabling the cracklib check during build

Release 1.4.3
* Multiple translation updates
* Add usersubstr check for substrings of N characters from the username
  patch by Danny Sauer
* Add --disable-cracklib-check configure parameter

Release 1.4.2
* Fix regression in handling retry, enforce_for_root, and
  local_users_only options introduced with the previous
  release.

Release 1.4.1
* pam_pwquality: Abort the retry loop if user requests it.
* Allow setting retry, enforce_for_root, and local_users_only options
  in the pwquality.conf config file.
* Fix uninitialized memory in word distance calculations.
* Fix possible one byte buffer underflow when parsing the config file.
* Return default cracklib dictionary path if not overriden.
* Update translations from Zanata.

Release 1.4.0
* Fix possible buffer overflow with data from /dev/urandom
  in pwquality_generate().
* Do not try to check presence of too short username in password.
  (thanks to Nikos Mavrogiannopoulos)
* Make the user name check optional (via usercheck option).
* Add an 'enforcing' option to make the checks to be warning-only
  in PAM.
* The difok = 0 setting will disable all old password similarity
  checks except new and old passwords being identical.
* Updated translations from Zanata.

Release 1.3.0
* Change the defaults for credits, difok, and minlen
* Make the cracklib check optional but on by default
* Add implicit support for parsing  <cfgfile>.d/*.conf files
* Add libpwquality API manual page

Release 1.2.4
* Add Python3 module subpackage

Release 1.2.3
* Fix problem with parsing the pam_pwquality options
  patch by Vladimir Sorokin.
* Updated translations from Transifex
* Treat empty user or password as NULL

Release 1.2.2

* Manual page fixes.
* Make it possible to set the maxsequence configuration value.
* Updated translations from Transifex.

Release 1.2.1

* Properly free pwquality settings.
* Add extern "C" to public header.
* Updated translations from Transifex.

Release 1.2.0

* Add maxsequence check for too long monotonic character sequence.
* Clarified alternative licensing to GPLv2+.
* Add local_users_only option to skip the pwquality checks for
  non-locals. (thanks to Stef Walter)

Release 1.1.1

* Use rpm built-in filtering of provides (fix for rhbz#830153)
* Remove strain debug fprintf() (fix for rhbz#831567)
* Make the Python bindings build optional (thanks to Colin Walters)
* Make the PAM module build optional (thanks to Jasper Lievisse Adriaanse)

Release 1.1.0

* Fixed a memory leak when throwing PWQError exception
* Added pkgconfig file (thanks to Matthias Classen)
* The simplicity checks are now called before the cracklib check
* Added enforce_for_root option to the PAM module
* Updated translations from Transifex

Release 1.0.0

* Added a check for words from user's GECOS
* Added a check for configurable words
* Added a check for maximum consecutive characters of the same class
* Fixed configuration file parsing (allowed '=' but not required)
* Fixed possible leak when string setting is set
* Project added to Transifex for localization

Release 0.9.9

* Release candidate for 1.0
* Added Python bindings
* Added user name parameter to the pwquality_check()
* Added manpages and other documentation
* Removed obsolete and unused difignore option

Release 0.9

* First prerelease
