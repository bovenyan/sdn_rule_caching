#ifndef REDREMOVAL_H
#define REDREMOVAL_H

#include <list>
#include <memory>
#include <map>
#include <cmath>
#include "RuleParsing.h"
#include "tools.h"

namespace Z{
	class Rule{
		public:
			std::vector<std::vector<unsigned int> > S;
			Rule(){
				S.resize(4);
				for (size_t i = 0; i  != S.size(); ++i)
				{
					S[i].resize(2);
				}
			}
	};



	class Node
	{
	public:
		std::vector<unsigned int> intervals;
		std::vector<Node> edges;

		Node(){};
		Node(const std::vector<unsigned int> & _intervals):intervals(_intervals){};
	};

	enum color
	{
		blue=0,green=1,yellow=2,white=3
	};

	struct edge_unsigned_int
	{
		unsigned int i;
		size_t edge_index;
		bool operator < (const edge_unsigned_int & other){
			return i < other.i;
		}
	};
	
	//rules-in, bucket-in, indexes-of-rules-out.
	void Redundancy_Filter(const std::vector<Z::Rule> &, const Z::Rule &, std::vector<std::size_t> &);
	
	void ORtoR(RuleList *, std::vector<unsigned short> &, std::vector<Rule> &);
	
}
#endif
