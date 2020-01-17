Firewall Task
=============

## Build

To build it, you need to have `libnetfilter_queue` and headers installed.

To get the binary run:

```
mkdir build
cd build
cmake ..
make
```

## Usage

To run, do a `./feuerwand ip port counter string` with apropriate parameters.

# Notes on Implementation

The implementation is straight forward.
It uses the example code and helper functions offered by lbnetfilter_queue for parsing IP and UDP headers.
It only supports IPv4 and UDP (because that's how I read the specification).
For message passing it uses two global variables (filter rule and decrementing counter).
This is not optimal but reduces complexity, because no message passing is required.
Since this application is single threaded, the global variables are a good tradeoff.

