#include "OFswitch.h"


// ----- OFswitch -------------
//
void OFswitch::init(){
	buckTree = NULL;
	ruleList = NULL;
	subnet[1] = 0;
	subnet[0] = 0;
}

// for real traces
inline bool OFswitch::parsePacket(string &str, packet &packInfo){
	vector<string> fields;	
	boost::split( fields, str, boost::is_any_of("%"));
	packInfo.timestamp = boost::lexical_cast<double>(fields[0].c_str());
	packInfo.predicate[0] = maskIP(fields[1]);
	packInfo.predicate[1] = maskIP(fields[2]);
	packInfo.predicate[2] = boost::lexical_cast<unsigned int>(fields[3]);
	packInfo.predicate[3] = boost::lexical_cast<unsigned int>(fields[4]);
	
	if (!insubnet(packInfo.predicate, subnet))
		return false;
	
	return true;
}


void OFswitch::ProcTrace(){
	// IO
	namespace fs = boost::filesystem;
	namespace io = boost::iostreams;
	fs::path dir(config.trace_file);
	fs::directory_iterator end;
	// int termCounter = 0;
	string line; 
	
	// 
	double initTime = -1.0;
	double nextCheckPoint = -1.0;
	packet pack;
	Cache cache(config.TCAMcap); 
	size_t queryNo;
	
	if (fs::exists(dir) && fs::is_directory(dir)){
		for( fs::directory_iterator itr(dir); itr != end; ++itr){
			if (fs::is_regular_file(itr->status())){
				cout << itr->path().c_str() <<endl;
				ifstream file(itr->path().c_str());
				try{
					io::filtering_istream in;
					in.push(io::gzip_decompressor());
					in.push(file);
					/*	
					if (termCounter< 10){
						termCounter++;
						continue;
					}*/

					if (initTime < 0){ // lose one packet for timestamp initialization
						getline(in, line); 
						parsePacket(line, pack);
						initTime = pack.timestamp;
						nextCheckPoint = initTime + config.samplingTime;
					}

					for(line = ""; getline(in, line);){
						if (pack.timestamp - initTime > config.testDur){ // test ends
							return;
						}

						if(!parsePacket(line, pack)) // process pack
							continue;
						
						OneBucket * effBuck = buckTree->searchBucket(pack.predicate, buckTree->bucketRoot);
						queryNo = cache.Query_TO(effBuck, pack.timestamp+config.buckTimeOut, pack.timestamp);
						if (queryNo == 0)
							stat.hitNo++;
						else
							stat.missNo+=queryNo;

						if (pack.timestamp >= nextCheckPoint){ // sampling check
							nextCheckPoint += config.samplingTime;
							fetchStat(pack.timestamp);
						}
					}

				}
				catch(const boost::iostreams::gzip_error & e){
					cout<<e.what()<<endl;
				}
				file.close();
			}
		}
	}
}

inline void OFswitch::fetchStat(double curTime){

}

// for synthetic traces
inline bool OFswitch::parseHeader_syn(string & str, packet &packInfo, double prevTime, default_random_engine & gen, exponential_distribution<double> & ts_dist, istream dur_file){
	vector<string> fields;	
	boost::split( fields, str, boost::is_any_of("\t"));
	packInfo.timestamp = prevTime + ts_dist(gen);
	packInfo.predicate[0] = unsigned(atoi(fields[0].c_str()));
	packInfo.predicate[1] = unsigned(atoi(fields[1].c_str()));
	packInfo.predicate[2] = unsigned(atoi(fields[2].c_str()));
	packInfo.predicate[3] = unsigned(atoi(fields[3].c_str()));
	string dur_str;
	getline(dur_file, dur_str);
	packInfo.duration = stod(dur_str);

	
	if (!insubnet(packInfo.predicate, subnet))
		return false;
	return true;
}

void OFswitch::ProcTrace_syn(bool to_lru){
	// IO
	ifstream trace(config.trace_file.c_str());
	string line;
	default_random_engine gen;
	
	// flowGen
	exponential_distribution<double> distr_arr(config.arr_lambda);
	exponential_distribution<double> distr_dur(config.dur_lambda);
	
	// Caching & record
	
	// intermediate variable
	double curTime = 0.0;
	packet pack;
	OneBucket * effBuck = NULL;
	size_t queryNo = 0;
	int nextCheckPoint = config.samplingTime;
	
	if (to_lru){ // TimeOut, measure space
		Cache cache(config.buckTimeOut);
		while (curTime < config.testDur || !trace.eof()){
			getline(trace, line);
			curTime = pack.timestamp;
			if (!parseHeader_syn(line, pack, curTime, gen, distr_arr, distr_dur))
				continue;
			effBuck = buckTree->searchBucket(pack.predicate, buckTree->bucketRoot);
			if (effBuck == NULL) // not found;
				continue;

			if (cache.Query_TO(effBuck, pack.timestamp+pack.duration, pack.timestamp)){
				stat.hitNo++;
			}
			else{
				stat.missNo++;
			}

			if (curTime > nextCheckPoint){
				nextCheckPoint += config.samplingTime;
				cache.cleanup_TO(pack.timestamp);
			}
		}
	}
	else{ // LRU, measure delay
		size_t token = 0;
		double nextTokenTime = 0;
		size_t genToken = 0;
		Cache cache(config.TCAMcap);
		while (curTime < config.testDur || !trace.eof()){
			getline(trace, line);
			curTime = pack.timestamp;
			if (!parseHeader_syn(line, pack, curTime, gen, distr_arr, distr_dur))
				continue;
			effBuck = buckTree->searchBucket(pack.predicate, buckTree->bucketRoot);
			if (effBuck == NULL) // not found;
				continue;
			
			queryNo = cache.Query_LRU(effBuck, pack.timestamp+pack.duration, pack.timestamp);
			
			if (queryNo == 0)
				stat.hitNo++;
			else{
				stat.missNo += queryNo;
				// queuing delay
				if (nextTokenTime < curTime){ // get token generated
					genToken = size_t((curTime-nextTokenTime)/config.tokenGenInt);
					nextTokenTime += genToken*config.tokenGenInt;
					token += (genToken-queryNo);
					if (token > config.maxTokenNo)
						token = config.maxTokenNo;
				}

				if (token >= queryNo ){ // more token, no qDelay;
					genToken = size_t((curTime-nextTokenTime)/config.tokenGenInt);
					token -= queryNo;
				}
				else{
					nextTokenTime += ((queryNo - token) * config.tokenGenInt);
					stat.qDelay += (nextTokenTime-config.tokenGenInt-curTime);
				}

				// transmission delay
				stat.tDelay += queryNo/config.bandwidth;
			}
		}
	}
}

