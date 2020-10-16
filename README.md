# htpasswd

A compatible, stand-alone implementation of the Apache htpasswd utility in Go.

Version control: https://git.sr.ht/~flimberger/htpasswd
Issues: https://todo.sr.ht/~flimberger/htpasswd

## Motivation and Goals

On some systems,
e.g. FreeBSD,
the Apache webserver utilities are not packaged separately.
The only practical alternative seems to be
[py-htpasswd](http://trac.edgewall.org/browser/trunk/contrib/htpasswd.py),
which didn't work for me.

Therefore,
the goal of this project is to provide a portable, stand-alone implementation of
the `htpasswd` utility.

## Known Issues

This project is still in the early stages of its development,
there may be unknown reliability or performance issues.

- The flags are implemented using the standard libraries `flag` package.
  This means `getopt(3)`-like flag grouping is not supported.
- Windows support is completely missing.
  Send patches.

## Documentation

- https://httpd.apache.org/docs/2.4/en/programs/htpasswd.html
- https://httpd.apache.org/docs/2.4/misc/password_encryptions.html

## License

This software is licensed under the terms of the
[ISC-license](https://opensource.org/licenses/ISC).
