The project contains a mix of technologies. All packet parsing and general low-level logic is implemented in pure C, using minimal libraries (libpcap). The resulting C functions are then called directly from GO (thanks to `cgo`, which allows C bindings). The only reason I'm using GO and not just C is to have an easier time creating the GUI by using Wails, which allows me to create a Vue app that gets turned into a desktop app. 

To actually have a reproducible build that is intended to work on multiple systems without massive headaches regarding the toolchain, Docker was used. All the necessary components were added to the image, and the files we actually care about were then exported from this image (this includes shared libraries like libpcap).

Running the project can be done in multiple ways. Locally, this can be done with both `./build.sh local` and `./build.sh dev`, but it requires that you have libcap available on your system (it is important that the libpcap version you're using is compiled with libnl, otherwise monitor mode doesn't work). But for a more portable approach, you can use `./build.sh docker`, which sets everything up inside of a docker container, and dumps the resulting files (as well as the shared libpcap library) in an `output` folder.

You need to run the resulting binary as root.

I have not tested this on Windows, but you may be able to run it under WSL. The only limitation is that I don't know if you'll be able to use a real network card to sniff packets. Just use linux :).