#ifndef OFSWITCH_H
#define OFSWITCH_H

#include "BucketTree.h"
#include "RuleParsing.h"
#include "tools.h"

struct packet{
	unsigned int predicate[4];
	double timestamp;
	double duration;
};

struct reqRec{
	OneBucket * bucket;
	double timestamp;

	reqRec():bucket(NULL), timestamp(0.0){};
	reqRec(OneBucket * ptr, double ts): bucket(ptr), timestamp(ts){};
};

struct configuration{
	// simulation parameter
	string trace_file;
	int testDur;
	int samplingTime;
	string subnet_s;
	// controller
	double tokenGenInt;
	size_t maxTokenNo;
	double bandwidth;
	// switch
	double buckTimeOut;
	size_t TCAMcap;
	// packetGenerator
	double arr_lambda;
	double dur_lambda;

	configuration():trace_file(""), testDur(0), samplingTime(0), tokenGenInt(1), 
	maxTokenNo(0), bandwidth(0), buckTimeOut(0.0), TCAMcap(0), arr_lambda(1.0),
	dur_lambda(1.0), subnet_s(""){};
};

struct statistics{
	size_t hitNo;
	size_t missNo;
	double qDelay;
	double tDelay;
	size_t rule_downNo;
	size_t TCAM_usage;
	
	statistics():hitNo(0), missNo(0), qDelay(0.0), tDelay(0.0), rule_downNo(0), TCAM_usage(0){};
};

class Cache{
	typedef list<reqRec>::iterator ListIterType;
	typedef unordered_map<OneBucket*, ListIterType>::iterator MapIterType;
	typedef unordered_map<OneBucket*, double>::iterator MapIterType_to;
	
	private:
	unordered_map<OneBucket*, double> cacheTable_to;
	unordered_map<OneBucket*, ListIterType> cacheTable_lru;
	list<reqRec> lru_que;

	public:
	size_t CacheSize;
	// for Time-Out
	double timeOut;
	// for LRU
	size_t Capacity;
	const size_t FREQ_KICKOUT;
	size_t kicktime;

	Cache():CacheSize(0), timeOut(0.0), Capacity(0), FREQ_KICKOUT(0){};

	Cache(double to): Cache() {
		CacheSize = 0;
		timeOut = to;
	}

	Cache(size_t cap, size_t freq_k = 500): FREQ_KICKOUT(freq_k){
		CacheSize = 0;
		Capacity = cap;
	}
	
	inline bool Query_TO(OneBucket * qBuck, double ts, double curT){
		pair<OneBucket *, double > request (qBuck, ts+timeOut);
		pair<MapIterType_to, bool > result = cacheTable_to.insert(request);

		if (result.second){ // there isn't
			return false;
		}
		else{
			if (result.first->second < curT)
				return false;
			else{
				if (result.first->second < ts+timeOut)
					result.first->second = ts+timeOut;
				return true;
			}
		}
	}

	inline void cleanup_TO(double curTime){
		CacheSize = 0;
		for (auto iter = cacheTable_to.begin(); iter != cacheTable_to.end(); ){
			if (iter->second < curTime)
				iter = cacheTable_to.erase(iter);
			else{
				iter++;
				CacheSize++;
				// CacheSize += (1 + iter->first->relaRules.size());
			}
		}
	}

	inline size_t Query_LRU(OneBucket * qBuck, double ts, double curT){
		pair<OneBucket *, ListIterType > request (qBuck, lru_que.end());
		pair<MapIterType, bool > result = cacheTable_lru.insert(request);
		
		kicktime = 0;	
		
		if (result.second){  // there isn't
			reqRec entry(qBuck, ts);
			lru_que.push_front(entry);
			result.first->second = lru_que.begin();
			CacheSize ++;
			//CacheSize += (1+result.first->first->relaRules.size());
			
			
			while (CacheSize > Capacity){ // kick LRU
				cacheTable_lru.erase( cacheTable_lru.find(lru_que.rbegin()->bucket)); // careful	
				
				if (curT < lru_que.rbegin()->timestamp){ // kick an in-use
					lru_que.push_front(*lru_que.rbegin());
					lru_que.pop_back();	
				}
				else{
					CacheSize--;
					// CacheSize -= (1+result.first->first->relaRules.size());
					lru_que.pop_back();
				}
				kicktime ++;
				
				if (kicktime > FREQ_KICKOUT){
					cout<<"Not Enough TCAM Capacity" <<endl;
					exit(0);
				}
			}
		}
		
		else{ 
			if (ts > result.first->second->timestamp){
				reqRec entry(qBuck, ts);
				lru_que.push_front(entry);
			}
			else
				lru_que.push_front(*result.first->second);

			lru_que.erase(result.first->second);
			result.first->second = lru_que.begin();		
		}
	
		return kicktime; 
	}
};

class OFswitch{
	public:
	// for source
	BucketTree * buckTree;
	RuleList * ruleList;
	// for storage
	Cache *tcam;

	// configuration and stat
	configuration config;
	statistics stat;
	size_t subnet[2];	
	
	OFswitch(){
		init();
	}

	OFswitch(RuleList * rl, BucketTree * bt, configuration conf){
		init();
		buckTree = bt;
		ruleList = rl;
		config = conf;
		
		// subnet;
		vector<string> fields;
		boost::split(fields, config.subnet_s, boost::is_any_of("/"));
		subnet[1] = atoi(fields[1].c_str());
		subnet[0] = maskIP(fields[0], subnet[1]);
	}

	void ProcTrace();

	void ProcTrace_syn(bool to_lru);


	private:

	void init();
	
	// for real traces
	inline bool parsePacket(string &, packet &); 

	inline void fetchStat(double);

	// for sythetic traces
	inline bool parseHeader_syn(string &, packet &, double, default_random_engine &, exponential_distribution<double> &, exponential_distribution<double> &);
	
};

#endif
