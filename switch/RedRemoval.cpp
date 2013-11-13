#include "RedRemoval.h"
using Z::Node; using Z::Rule; using Z::edge_unsigned_int; using Z::color;



void add_rule_to_subtree(Node & SpaceRoot,const Rule & rule, unsigned short m) 
{
	if (m < rule.S.size())
	{
		Node n(rule.S[m]);
		add_rule_to_subtree(n,rule,m+1);
		SpaceRoot.edges.push_back(n);
	}
}

void remove_edges( Node & SpaceRoot, const vector<size_t> & erasing_edges ) 
{
	for (size_t i = 0; i < erasing_edges.size(); ++i)
	{
		SpaceRoot.edges.erase(SpaceRoot.edges.begin() + erasing_edges[i]);
	}
}

void add_edges( Node & SpaceRoot, const vector<Node> & adding_edges ) 
{
	for(size_t i = 0; i < adding_edges.size(); ++i){
		SpaceRoot.edges.push_back(adding_edges[i]);
	}
}

// A intersect B

bool intersection(unsigned int i_1_b, unsigned int i_1_e, unsigned int i_2_b, unsigned int i_2_e, unsigned int & itc_b, unsigned int & itc_e){
	assert(i_1_b <= i_1_e);
	assert(i_2_b <= i_2_e);

	itc_b = i_1_b > i_2_b ? i_1_b : i_2_b;
	itc_e = i_1_e < i_2_e ? i_1_e : i_2_e;

	if (itc_b > itc_e)
	{
		return false;
	}else{
		return true;
	}
} 

void merg_continue(std::vector<unsigned int> & v){
	if (v.empty())
	{
		return;
	}
	assert(v.size() % 2 ==0);
	unsigned int tail = v[1];
	for (size_t i = 2; i != v.size(); i+= 2)
	{
		if (v[i] == tail + 1)
		{
			v.erase(v.begin() + i);
			i--;
			v.erase(v.begin() + i);
			i--;
		}
		tail = v[i+1];
	}
}


// A1 A2 A3 ... compelementary
bool compelementary(const std::vector<unsigned int> & set, std::vector<unsigned int> & cmp_set){
	assert(set.size() >= 2);
	for (size_t i = 0; i != set.size(); i+=2)
	{
		unsigned int b = 0, e=0xffffffff;
		if (set[i] != 0)
		{
			b = set[i] - 1;
		}

		if (set[i + 1] != 0xffffffff)
		{
			e = set[i + 1] + 1;
		}


		if (b <= e)
		{
			if (b != 0)
			{
				cmp_set.push_back(b);

			}

			if (e != 0xffffffff)
			{
				cmp_set.push_back(e);
			}
		}
	}

	if (set.front() != 0)
	{
		cmp_set.insert(cmp_set.begin(),0);
	}

	if (set.back() != 0xffffffff)
	{
		cmp_set.push_back(0xffffffff);
	}
	assert(cmp_set.size() % 2 == 0);

	if (cmp_set.empty())
	{
		return false;
	}
	else 
		return true;
}

bool cmp( Node & SpaceRoot, const Rule & rule, unsigned short m, vector<unsigned int> & new_edge_interval ) 
{
	bool rs = false;
	vector<unsigned int> intervals;
	for (vector<Node>::iterator i = SpaceRoot.edges.begin(); i != SpaceRoot.edges.end(); ++i) // auto - vector<Node> iterator
	{
		intervals.insert(intervals.end(),i->intervals.begin(),i->intervals.end());
	}
	std::sort(intervals.begin(),intervals.end());
	vector<unsigned int> cmp_set; 
	merg_continue(intervals);
	compelementary(intervals,cmp_set);
	for (size_t i = 0;  i != cmp_set.size(); i += 2)
	{
		unsigned int b = cmp_set[i];
		unsigned int e = cmp_set[i + 1];
		unsigned int itsc_b = 0;
		unsigned int itsc_e = 0;
		if (intersection(b,e,rule.S[m].front(), rule.S[m].back(),itsc_b,itsc_e))
		{
			rs = true;
			new_edge_interval.push_back(itsc_b);
			new_edge_interval.push_back(itsc_e);
		}
	}
	return rs;
}

bool check_intersection( std::vector<unsigned int> & edge_intervals, const Rule & rule, unsigned short m, vector<unsigned int> & inter_set, vector<unsigned int> & rest ) 
{
	bool rs = false;
	vector<unsigned int> cmp_set;
	compelementary(rule.S[m],cmp_set);
	assert(cmp_set.size() % 2 == 0);
	for (size_t i = 0; i < edge_intervals.size(); i+= 2)
	{
		unsigned int b = edge_intervals[i];
		unsigned int e = edge_intervals[i+1];
		unsigned int itsc_b = 0,itsc_e = 0;
		if (intersection(b,e,rule.S[m].front(),rule.S[m].back(),itsc_b,itsc_e))
		{
			rs = true;
			inter_set.push_back(itsc_b);
			inter_set.push_back(itsc_e);
			for (size_t j = 0; j < cmp_set.size(); j += 2)
			{
				unsigned int cmp_b = cmp_set[j];
				unsigned int cmp_e = cmp_set[j + 1];
				unsigned int itsc_b = 0, itsc_e = 0;
				if (intersection(b,e, cmp_b,cmp_e,itsc_b,itsc_e))
				{
					rest.push_back(itsc_b);
					rest.push_back(itsc_e);
				}

			}
		}
	}	

	return rs;
}

bool append(Node & SpaceRoot , const Rule & rule, unsigned short m) 
{
	//if a rule is fully covered by previous rules, return false, otherwise return true.
	bool changed = false;

	vector<unsigned int> new_edge_interval;

	//Sm - (I1 union Ik)
	if (cmp(SpaceRoot,rule,m,new_edge_interval))
	{
		changed = true;
		Node n(new_edge_interval);
		add_rule_to_subtree(n,rule,m+1);
		SpaceRoot.edges.push_back(n);
	}

	if ( m < rule.S.size() - 1)
	{
		int new_edge_num = 0;
		for (size_t j = 0; j < SpaceRoot.edges.size()-new_edge_num; ++j)
		{
			vector<unsigned int> intersected_intervals;
			vector<unsigned int> rest_intervals;

			//if new rule intersect exiting rules
			if (check_intersection(SpaceRoot.edges[j].intervals, rule, m, intersected_intervals,rest_intervals))
			{
				merg_continue(intersected_intervals);
				//copy intersected node
				Node n = SpaceRoot.edges[j];
				n.intervals = intersected_intervals;

				//check new rule at next dimension, if different.
				if (append(n,rule,m+1))
				{
					changed = true;

					//add new rule node
					SpaceRoot.edges.push_back(n);
					new_edge_num++;

					if (!rest_intervals.empty())
					{
						//if there is still some intervals left of old rule
						SpaceRoot.edges[j].intervals = rest_intervals;
					}
					else
					{
						SpaceRoot.edges.erase(SpaceRoot.edges.begin() + j);
						--j;
					}
				}
			}
		}
	}
	return changed;
}

bool bucket_filter( const Rule & rule_in, const Rule & bucket_boundary, Rule & rule_out ) 
{
	bool in_bucket = true;
	for (size_t i = 0; i != rule_in.S.size(); ++i)
	{
		unsigned int inter_b = 0, inter_e = 0;
		if (intersection(rule_in.S[i].front(),rule_in.S[i].back(),bucket_boundary.S[i].front(),bucket_boundary.S[i].back(),inter_b,inter_e))
		{
			rule_out.S[i][0] = inter_b;
			rule_out.S[i][1] = inter_e;
		}
		else
		{
			in_bucket = false;
			break;
		}
	}
	return in_bucket;
}

void Z::Redundancy_Filter(const std::vector<Rule> & RuleData, const Rule & bucket_boundary, std::vector<std::size_t> & rules_idx_wo_rddcy){
	if (RuleData.empty())
		return ;
	//Bo: rule count;
	int effcounter = 0;
	for (size_t i = 0; i < RuleData.size(); ++i){
		const Rule &r = RuleData[i];
		Rule backet_r;
		if (!bucket_filter(r, bucket_boundary, backet_r)){
			continue;
		}
		effcounter++;
	}

	
	Node SpaceRoot;

	bool firstHit = false;

	for (size_t i = 0; i != RuleData.size(); ++i)
	{
		const Rule &r = RuleData[i];
		Rule backet_r;
		if (!bucket_filter(r,bucket_boundary,backet_r))
		{
			continue;
		}
		
		if (!firstHit){ 
			add_rule_to_subtree(SpaceRoot, RuleData[i], 0);
			rules_idx_wo_rddcy.push_back(i);
			firstHit = true;
		}
		else{
			if (append(SpaceRoot,backet_r,0))
			{
				rules_idx_wo_rddcy.push_back(i);
			}
		}
	}
}


void Z::ORtoR(RuleList * ruleObj, std::vector<unsigned short> & relaRuleID, std::vector<Rule> & FDDruleList){
	vector<OneRule> & rule_r = ruleObj->handle;
	for (size_t i = 0; i < relaRuleID.size(); i++){
		unsigned short int ID = relaRuleID[i];
		OneRule & one_rule = rule_r[ID];
		Rule FDDrule;
		
		// convert to range rule
		if (one_rule.srcIP_i[1] == 0){
			FDDrule.S[0][0] = 0;
			FDDrule.S[0][1] = 0xffffffff;
		}
		else{
			FDDrule.S[0][0] = one_rule.srcIP_i[0];
			FDDrule.S[0][1] = one_rule.srcIP_i[0] + ( (1 << (32 - one_rule.srcIP_i[1])) -1);
		}


		if (one_rule.dstIP_i[1] == 0){
			FDDrule.S[1][0] = 0;
			FDDrule.S[1][1] = 0xffffffff;
		}
		else{
			FDDrule.S[1][0] = one_rule.dstIP_i[0];
			FDDrule.S[1][1] = one_rule.dstIP_i[0] + ( (1 << (32 - one_rule.dstIP_i[1])) -1);
		}
		
		FDDrule.S[2][0] = one_rule.srcP_i[0];
		FDDrule.S[2][1] = one_rule.srcP_i[1];
		FDDrule.S[3][0] = one_rule.dstP_i[0];
		FDDrule.S[3][1] = one_rule.dstP_i[1];
					
		FDDruleList.push_back(FDDrule);
	}

}

/*
void Z::convert_format(RuleList & rules, vector<Rule> & ruledata){
	vector<OneRule> & rules_r = rules.handle;
	for (size_t i = 0; i < rules_r.size(); i++)
	{
		OneRule & one_rule = rules_r[i];
		Rule c_one_rule;
		if(one_rule.srcIP_i[1] == 0){
			c_one_rule.S[0][0] = 0;
			c_one_rule.S[0][1] = 0xffffffff;
		}else{
			c_one_rule.S[0][0] = one_rule.srcIP_i[0];
			c_one_rule.S[0][1] = one_rule.srcIP_i[0] +(( 1 << (32 - one_rule.srcIP_i[1])) - 1);
		}

		if (one_rule.dstIP_i[1] == 0)
		{
			c_one_rule.S[1][0] = 0;
			c_one_rule.S[1][1] = 0xffffffff;
		}else{
			c_one_rule.S[1][0] = one_rule.dstIP_i[0];
			c_one_rule.S[1][1] = one_rule.dstIP_i[0] +(( 1 << (32 - one_rule.dstIP_i[1])) - 1);
		}
		c_one_rule.S[2] = one_rule.srcP_i;
		c_one_rule.S[3] = one_rule.dstP_i;
		ruledata.push_back(c_one_rule);
		
		cout << "IP src : " << c_one_rule.S[0][0] << " -> " <<c_one_rule.S[0][1]<<endl;
		cout << "IP dst : " << c_one_rule.S[1][0] << " -> " <<c_one_rule.S[1][1]<<endl;
		cout << "Port src : " << c_one_rule.S[2][0] << " -> " <<c_one_rule.S[2][1]<<endl;
		cout << "Port dst : " << c_one_rule.S[3][0] << " -> " <<c_one_rule.S[3][1]<<endl;
		cout << endl;
	}
}*/

