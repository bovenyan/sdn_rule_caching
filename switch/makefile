BOOST_ROOT=/usr/local/boost_1_54_0
# OBJS = unittest.o RedRemoval.o RuleParsing.o tools.o BucketTree.o OFswitch.o
OBJS = unittest.o RedRemoval.o RuleParsing.o tools.o BucketTree.o 
CC = g++
DEBUG = -g
BOOST_L = -L $(BOOST_ROOT)/stage/lib 
BOOST_DYN = -lboost_system -lboost_filesystem -lboost_iostreams -lboost_serialization -lz
BOOST_I = -I $(BOOST_ROOT)/boost
CFLAGS= -std=c++11 -Wall -c $(DEBUG)
LFLAGS= -std=c++11 -Wall $(DEBUG)

demo.out: $(OBJS)
	$(CC) $(BOOST_L) $(LFLAGS) $(OBJS) $(BOOST_DYN) -o demo.out 

unittest.o: unittest.cpp tools.h
	$(CC) $(BOOST_I) $(CFLAGS) unittest.cpp
	
RedRemoval.o: tools.h RuleParsing.h RedRemoval.h RedRemoval.cpp
	$(CC) $(BOOST_I) $(CFLAGS) RedRemoval.cpp

RuleParsing.o: RuleParsing.h RuleParsing.cpp tools.h
	$(CC) $(BOOST_I) $(CFLAGS) RuleParsing.cpp

tools.o: tools.h tools.cpp
	$(CC) $(BOOST_I) $(CFLAGS) tools.cpp
	
BucketTree.o: BucketTree.h BucketTree.cpp tools.h RuleParsing.h RedRemoval.h
	$(CC) $(BOOST_I) $(CFLAGS) BucketTree.cpp

#OFswitch.o: OFswitch.h OFswitch.cpp BucketTree.h RuleParsing.h tools.h
#	$(CC) $(BOOST_I) $(CFLAGS) OFswitch.cpp

clean:
	\rm *.o *~ demo.out
tar:
	tar cfv switchDemo.tar RuleParsing.h RuleParsing.cpp BucketTree.h BucketTree.cpp tools.h tools.cpp makefile RedRemoval.h RedRemoval.cpp OFswitch.h OFswitch.cpp unittest.cpp README .ycm_extra_conf.py
