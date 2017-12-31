DigiByte Core 0.13.2
=====================

Setup
---------------------
[DigiByte Core](http://digibyte.org/en/download) is the original DigiByte client and it builds the backbone of the network. However, it downloads and stores the entire history of DigiByte transactions (which is currently several GBs); depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

Running
---------------------
The following are some helpful notes on how to run DigiByte on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/digibyte-qt` (GUI) or
- `bin/digibyted` (headless)

### Windows

Unpack the files into a directory, and then run digibyte-qt.exe.

### OS X

Drag DigiByte-Core to your applications folder, and then run DigiByte-Core.

### Need Help?

* See the documentation at the [DigiByte Wiki](https://digibyte.info/)
for help and more information.
* Ask for help on [#digibyte](http://webchat.freenode.net?channels=digibyte) on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net?channels=digibyte).
* Ask for help on the [DigiByteTalk](https://digibytetalk.io/) forums.

Building
---------------------
The following are developer notes on how to build DigiByte on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [OS X Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The DigiByte repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Multiwallet Qt Development](multiwallet-qt.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://dev.visucore.com/bitcoin/doxygen/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Unit Tests](unit-tests.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* Discuss on the [DigiByteTalk](https://digibytetalk.io/) forums.
* Discuss project-specific development on #digibyte on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net/?channels=digibyte).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)

License
---------------------
Distributed under the [MIT software license](http://www.opensource.org/licenses/mit-license.php).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
