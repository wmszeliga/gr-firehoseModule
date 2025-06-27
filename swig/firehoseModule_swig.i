/* -*- c++ -*- */

#define FIREHOSEMODULE_API

%include "gnuradio.i"           // the common stuff

//load generated python docstrings
%include "firehoseModule_swig_doc.i"

%{
#include "firehoseModule/source.h"
%}

%include "firehoseModule/source.h"
GR_SWIG_BLOCK_MAGIC2(firehoseModule, source);
