BOOST_ROOT=/usr/local/boost_1_54_0
OBJS = RuleParsing.o QuadTree.o test.o tools.o
CC = g++
DEBUG = -g
BOOST_L = -L $(BOOST_ROOT)/lib 
BOOST_I = -I $(BOOST_ROOT)/include
CFLAGS= -c -Wall $(DEBUG)
LFLAGS=-Wall $(DEBUG)

QuadTreeDemo.out: $(OBJS)
	$(CC) $(BOOST_L) $(LFLAGS) $(OBJS) -o QuadTreeDemo.out

tools.o: tools.h tools.cpp
	$(CC) $(BOOST_I) $(CFLAGS) tools.cpp
	
RuleParsing.o: tools.h RuleParsing.h RuleParsing.cpp
	$(CC) $(BOOST_I) $(CFLAGS) RuleParsing.cpp

QuadTree.o: QuadTree.h RuleParsing.h QuadTree.cpp
	$(CC) $(BOOST_I) $(CFLAGS) QuadTree.cpp

test.o: RuleParsing.h test.cpp 
	$(CC) $(CFLAGS) test.cpp 

	

clean:
	\rm *.o *~ QuadTreeDemo.out
tar:
	tar cfv QuadTree.tar Filters10k RuleParsing.h RuleParsing.cpp test.cpp QuadTree.h QuadTree.cpp tools.h tools.cpp makefile README .ycm_extra_conf.py
