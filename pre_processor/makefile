BOOST_ROOT=/usr/local/boost_1_54_0
OBJS = trace_parser.o trace_mapping.o pre_processor.o
CC = g++
DEBUG = -g
BOOST_L = -L $(BOOST_ROOT)/stage/lib 
BOOST_DYN = -lboost_system -lboost_filesystem -lboost_iostreams -lboost_program_options
BOOST_I = -I $(BOOST_ROOT)/boost
CFLAGS= -std=c++11 -Wall -c $(DEBUG)
LFLAGS= -std=c++11 -Wall $(DEBUG)


Processor.out: $(OBJS)
	$(CC) $(BOOST_L) $(LFLAGS) $(OBJS) $(BOOST_DYN) -lpcap -o Processor.out

pre_processor.o: trace_parser.h trace_mapping.h pre_processor.cpp
	$(CC) $(BOOST_I) $(CFLAGS) pre_processor.cpp

trace_parser.o: trace_parser.h trace_parser.cpp
	$(CC) $(BOOST_I) $(CFLAGS) trace_parser.cpp

trace_mapping.o: trace_mapping.h trace_mapping.cpp
	$(CC) $(BOOST_I) $(CFLAGS) trace_mapping.cpp

