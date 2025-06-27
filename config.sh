#!/usr/bin/bash

/usr/local/bin/cmake -DBoost_DIR=/opt/local/libexec/boost/1.71/lib/cmake/Boost-1.71.0 -DCMAKE_INSTALL_PREFIX=/opt/local ..
make
sudo make install
