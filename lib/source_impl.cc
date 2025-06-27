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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "source_impl.h"

namespace gr {
  namespace firehoseModule {

    source::sptr
    source::make()
    {
      return gnuradio::get_initial_sptr
        (new source_impl());
    }


    /*
     * The private constructor
     */
    source_impl::source_impl()
      : gr::sync_block("source",
              gr::io_signature::make(0, 0, 0),
	      gr::io_signature::make(0,0x100000,sizeof(gr_complex)))
    {
	    t0 = 0;
	    buffer_size = 0x100000;
	    // Allocate I and Q buffers
	    i_buf = new unsigned char [buffer_size];
	    q_buf = new unsigned char [buffer_size];
	    // Set the read index to the buffer length -1
	    //read_index = buffer_size -1; // start
	    read_index = 0; // start
	    // Set the write index to zero
	    write_index = 0; // end
	    dev[0] = 'e'; dev[1] = 'n'; dev[2] = '5';
	    handle = initialize_pcap(dev); // dev should be the interface name (i.e. eth0)
    }

    /*
     * Our virtual destructor.
     */
    source_impl::~source_impl()
    {
	    // Deallocate the I and Q buffers
	    delete[] i_buf;
	    delete[] q_buf;
    }

    int
    source_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      int buffer_idx;
      gr_complex *out = (gr_complex *)output_items[0];

      write_mutex.lock();
      int nsamples_available = (write_index-read_index) % buffer_size;
      write_mutex.unlock();
      int nout = std::min(nsamples_available,noutput_items);

      // Get that number of items and put them in the output buffer and convert to gr_complex
      for (int i = 0;i < nout; i++) {
        buffer_idx = (read_index + i) % buffer_size;
	int8_t real = (int8_t)i_buf[buffer_idx];
	int8_t imag = (int8_t)q_buf[buffer_idx];
	out[i] = gr_complex((float)real,(float)imag);
      }

      // Update the read index (get mutex, update index, release mutex)
      read_mutex.lock();
      read_index = (read_index + nout) % buffer_size;
      read_mutex.unlock();

      // Tell runtime system how many output items we produced.
      //fprintf(stderr,"Read %d; Write %d; Samples available %d\n",read_index,write_index,nsamples_available);
      return nout;
    }

    bool
    source_impl::start() 
    {
	    _running = true;
	    // Spawn a thread
	    _thread = gr::thread::thread(_read_loop,this);
	    // Update the write index (get mutex, update index, release mutex)
	    return true;
    }

    bool
    source_impl::stop()
    {
	    _running = false;
	    _thread.join();

	    return true;
    }

    void
    source_impl::_read_loop(source_impl *obj) {
	    obj->read_loop();
    }

    void
    source_impl::read_loop() {
            struct pcap_pkthdr *header;     /* The header that pcap gives us */
            const u_char *packet;           /* The actual packet */

	    // In a loop, check how much space there is between the read and write index
	    // Use PCAP to fetch packets and de-interleave into I and Q buffer
	    // Since each packet from PCAP has 960 samples, we need to increment
	    // our buffer pointer for each packet we read up to the buffer length
	    // then we start overwriting from the beginning
	    while (true) {
		// Get packets
		pcap_next_ex(handle,&header,&packet);
		unsigned int packets_read = deinterlace_packet(header,packet,write_index);

		// Update write index 
		write_mutex.lock();
		write_index = (write_index + packets_read) % buffer_size;
		write_mutex.unlock();
	    }
    }

    unsigned int
    source_impl::deinterlace_packet(const struct pcap_pkthdr *header, const u_char *packet,const int buffer_offset)
    {
	unsigned int packets_read = 0;
	int buffer_idx = buffer_offset % buffer_size;
	unsigned char xi,xq;
	long long timestamp,delta;
	int result;

	if (header->len != 1462) {
		fprintf(stderr,"Trouble Trouble Trouble: (header->len != 1462)\n");
		return 0;
	}

	/* Some timestamp foolishness */
	timestamp = ((long long)packet[14]<<56) |
		    ((long long)packet[15]<<48) |
		    ((long long)packet[16]<<40) |
		    ((long long)packet[17]<<32) |
		    ((long long)packet[18]<<24) |
		    ((long long)packet[19]<<16) |
		    ((long long)packet[20]<<8)  |
		    ((long long)packet[21]<<0);
	delta = timestamp - t0;
	if (t0 == 0) { 
		t0 = timestamp;
		return 0; 
	}
	if ((delta < 0) || ((delta%960) != 0)) {
		fprintf(stderr,"Trouble Trouble Trouble: (delta mod 960 != 0)\n");
		return 0;
	}
	while (delta > 960) {
		fprintf(stderr,"timestamp: %08llx t0: %08llx delta: %lld\n",timestamp,t0,delta);
		unsigned char *i_ptr = i_buf;
		unsigned char *q_ptr = q_buf;
		// Write out some zeros to this portion of the buffer
		memset(i_ptr+buffer_idx,0,960);
		memset(q_ptr+buffer_idx,0,960);
		// Increment the number of packets read (for the output count)
		packets_read += 960;
		// Increment where the actual data buffer will start
		buffer_idx = (buffer_idx + 960) % buffer_size;
		delta -= 960;
	}
        /* Write the actual data */	
	int chan = 1;
	for (int i=0;i<960;i++) {
		buffer_idx = (buffer_idx + i) % buffer_size; // Allow wrap-around for the buffer
		get_sample(&packet[22],6*i+2*(chan-1),&xi);
		get_sample(&packet[22],6*i+2*(chan-1)+1,&xq);
		i_buf[buffer_idx] = 2*xi - 3;
		q_buf[buffer_idx] = 2*xq - 3;
	}
	packets_read += 960;
	t0 = timestamp;

	return packets_read;
    }

    void 
    source_impl::get_sample(const unsigned char buf[],int s,unsigned char *x) 
    {
        int byte_offset = s/4;
        int samp_offset = 3-(s%4);
        *x = (buf[byte_offset] >> (2*samp_offset)) & 3;
    }

    pcap_t *
    source_impl::initialize_pcap(char *dev) 
    {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "ether proto 0x88b5";	/* The filter expression */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	pcap_t *handle;

	handle = pcap_create(dev,errbuf);
	// Need to set the buffer size before the we activate the handle
	int buffer_size = 50*1024*1024; // 50 Mb
	if (pcap_set_buffer_size(handle,buffer_size) != 0) {
		fprintf(stderr, "Couldn't set buffer size %d: %s\n", buffer_size, pcap_geterr(handle));
		return NULL;
	}
	int snaplen = 65536;
	if (pcap_set_promisc(handle,1) != 0) {
		fprintf(stderr,"Could not set promiscuous mode%s\n",pcap_geterr(handle));
		return NULL;
	}
	if (pcap_set_snaplen(handle,snaplen) != 0) {
		fprintf(stderr,"Could not set snapshot length%s\n",pcap_geterr(handle));
		return NULL;
	}
	fprintf(stderr,"SnapLen size set to %d\n",snaplen);
	if (pcap_set_timeout(handle,1000) != 0) {
		fprintf(stderr,"Could not set timeout%s\n",pcap_geterr(handle));
		return NULL;
	}
	if (pcap_activate(handle) != 0) {
		fprintf(stderr,"Could not activate handle %s\n",pcap_geterr(handle));
		return NULL;
	}
	if (pcap_compile(handle,&fp,filter_exp,0,net) == -1) {
		fprintf(stderr,"Could not parse filter %s: %s\n",filter_exp,pcap_geterr(handle));
		return NULL;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return NULL;
	}

	return handle;
     }
  } /* namespace firehoseModule */
} /* namespace gr */

