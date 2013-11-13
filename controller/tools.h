#ifndef __TOOLS_H
#define __TOOLS_H

// This is an pre-compiling information which includes globally neccessary libs.

#include <vector>
#include <bitset>
#include <string>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>

using namespace std;

string get_dotDeci(const unsigned int (&)[2]);// transfer pref/mask to dot deci string


unsigned int maskIP(string, unsigned int = 0); // transfer dot deci string to pref/mask 

bool classPack(const unsigned int (&)[4], const unsigned int (&)[4][2]);

bool match(const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2]); // check whether certain rule matches certain bucket

bool match_check(const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2], bool &); // check whether certain rule is default that mask whole bucket

bool rule_bucket_redu(const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2], const unsigned int (&)[2]); // check whether a rule is redundant because of covering rule

void to_range(const unsigned int (&)[2], unsigned int (&)[2]);
#endif
