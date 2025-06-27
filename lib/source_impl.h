/* -*- c++ -*- */
/*
 * Copyright 2025 Walter Szeliga.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_FIREHOSEMODULE_SOURCE_IMPL_H
#define INCLUDED_FIREHOSEMODULE_SOURCE_IMPL_H

#include <gnuradio/thread/thread.h>
#include <firehoseModule/source.h>
#include <pcap.h>

namespace gr {
  namespace firehoseModule {

    class source_impl : public source
    {
     private:
      bool _running;
      unsigned char *i_buf;
      unsigned char *q_buf; 
      char dev[15];
      size_t buffer_size;
      unsigned int read_index;
      unsigned int write_index;
      long long t0;
      std::mutex read_mutex;
      std::mutex write_mutex;
      gr::thread::thread _thread;
      pcap_t *handle;
      static void _read_loop(source_impl *obj);
      void read_loop();
      unsigned int deinterlace_packet(const struct pcap_pkthdr *header, const u_char *packet, const int buffer_offset);
      void get_sample(const unsigned char buf[], int s,unsigned char *x);
      pcap_t *initialize_pcap(char *dev);

     protected:
      bool start();
      bool stop();

     public:
      source_impl();
      ~source_impl();

      // Where all the action really happens
      int work(
              int noutput_items,
              gr_vector_const_void_star &input_items,
              gr_vector_void_star &output_items
      );
    };

  } // namespace firehoseModule
} // namespace gr

#endif /* INCLUDED_FIREHOSEMODULE_SOURCE_IMPL_H */

