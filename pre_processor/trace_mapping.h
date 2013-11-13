#ifndef __TRACE_MAPPER_H
#define __TRACE_MAPPER_H


#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <vector>
#include <queue>
#include <stack>
#include <random>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
// for per-packet mapping
void Pack_mapping(const char*, const char*, const char*, size_t = 0);



// for per-flow mapping

class flow{
	public:
	double stime;
	double dur;
	
	flow(){stime = 0.0; dur = 0.0;};
	
	flow(double st, double dt):stime(st),dur(dt){};
	
	bool operator< (const flow& other) const{
		return (stime < other.stime); 
	}
};

size_t Flow_mapping(const char*, const char*, const char*, size_t = 0, bool =false, double = 0.001);


#endif
