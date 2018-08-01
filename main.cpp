#include <iostream>
#include <fstream>
#include <sstream>  
// #include "sha256.h"
#include "tcp/tcp_client.hpp"
#include "bigint.h"
#include <unistd.h>
#include <jsoncpp/json/json.h>
#include <cctype> // is*
#include<stdlib.h>
#include<time.h>
#include <openssl/sha.h>

using namespace std;
#define max_times 100000
int times;
int to_int(int c) 
{
  // if (not isxdigit(c)) return -1; // error: non-hexadecimal digit found
  if (isdigit(c)) 
    return c - '0';
  if (isupper(c)) c = tolower(c);
  return c - 'a' + 10;
}

char to_char(int c)
{
    return c >= 10? c - 10 + 'a': c + '0';
}


unsigned char * unhexlify(const string &input) 
{
    unsigned char * result = new unsigned char [input.size()/2+1];

    for(unsigned int i = 0,j = 0; i + 1 < input.size(); i+=2, j++)
    {
        int top = to_int(input[i]);
        int bot = to_int(input[i+1]);
        // cout<<"top = "<<top<<"  bot = "<<bot<<endl;

        result[j] = (top << 4) + bot;
        // cout<<(top << 4) + bot<<endl;
    }
    return result;
}


unsigned char * unhexlify(const char * input, int input_size) 
{
    unsigned char * result = new unsigned char [input_size/2+1];

    for(unsigned int i = 0,j = 0; i + 1 < input_size; i+=2, j++)
    {
        int top = to_int(input[i]);
        int bot = to_int(input[i+1]);
        // cout<<"top = "<<top<<"  bot = "<<bot<<endl;

        result[j] = (top << 4) + bot;
        // cout<<(top << 4) + bot<<endl;
    }
    return result;
}


string hexlify(const string &input)
{
    string result;
    result.reserve(input.size()*2+1);
    for(unsigned int i = 0; i < input.size(); i++)
    {
        // cout<<int(input[i])<<endl;
        int top = input[i] >> 4;
        int bot = input[i] % 16;
        // cout<<"top = "<<top<<"  bot = "<<bot<<endl;
        result.push_back(to_char(top));
        result.push_back(to_char(bot));
    }
    return result;

}

string hexlify(const unsigned char * input, int input_size)
{
    string result;
    result.reserve(input_size*2+1);
    for(unsigned int i = 0; i < input_size; i++)
    {
        // cout<<int(input[i])<<endl;
        int top = input[i] >> 4;
        int bot = input[i] % 16;
        // cout<<"top = "<<top<<"  bot = "<<bot<<endl;
        result.push_back(to_char(top));
        result.push_back(to_char(bot));
    }
    return result;

}


Dodecahedron::Bigint string2Bigint(const string & in)
{
    Dodecahedron::Bigint res = 0;
    for(unsigned int i = 0; i < in.size(); i++)
    {
        res = res * 16 + to_int(in[i]);
    }
    return res;
}

Dodecahedron::Bigint unsignedCharArray2Bigint(const unsigned char * in, int in_size) //little \xab\xcd -> \xcd\xab
{
    Dodecahedron::Bigint res = 0;
    for(int i = in_size - 1; i >= 0; i--)
    {
        res  = res * 256 + in[i];

        // int bot = in[i] >> 4;
        // int top = in[i] % 16;
        // res = res * 16 + top;
        // res = res * 16 + bot;
        // res = res * 16 + in[i];
    }
    return res;
}

char * table = "0123456789abcdef";


class Stratum
{
public:
    string hostname;
    int port;
    string username;
    string password;

    int msgId;
    tcp::TCPClient tcpClient;
    bool isConnected;
    bool isRunning;
    string status; // "subscribe" "authorize" "process"

    // string nonce1;
    unsigned char * nonce1 = NULL; // 16 char 8 byte  // 不同矿池不同， 考虑通用性，需要加入长度
    unsigned int nonce1_size;

    unsigned char * nonce2 = NULL; // 48 char 24 byte // 不同矿池不同， 考虑通用性，需要加入长度
    unsigned int nonce2_size;

    Dodecahedron::Bigint target;

    // hash rate
    unsigned int startTime;
    unsigned int solnTimes;
    float hashRate;
    float limitHashRate;

    string job_id;
    unsigned char * version = NULL;
    unsigned char *  prev_hash = NULL;
    unsigned char * merkle_root = NULL;
    unsigned char * reserved = NULL;
    unsigned char * ntime = NULL;
    unsigned char * nbits = NULL;
    bool clean_job;


    Stratum(){}
    Stratum(string hostname,int port,string username, string password)
    {
        this->hostname = hostname;
        this->port = port;
        this->username = username;
        this->password = password;
        this->msgId = 0;
        this->isRunning = true;
        this->isConnected = false;
        // this->nonce2 = new unsigned char[24];
        // memset(this->nonce2,0,24);

        this->startTime = time(0);
        this->solnTimes = 0;
        this->hashRate = 0.0;
        this->limitHashRate = 100.0; //k


        srand((int)time(0));

    }
    ~Stratum()
    {
        this->tcpClient.close();
    }

public:
    void connect(){
        this->tcpClient.setup(this->hostname, this->port);
        this->isConnected = true;


    }
    void subscribe()
    {

        ostringstream ostr;
        ostr << "{\"method\": \"mining.subscribe\","
        <<" \"id\": "<<this->msgId++
        <<", \"params\": [\""
        <<"slush/great/16.10\", null, \""
        <<this->hostname<<"\", "<<this->port<<"]}\n";
        this->tcpClient.send(ostr.str());
        this->status = "subscribe";

    }

    void authorize()
    {
        ostringstream ostr;
        ostr << "{\""
        <<"method\": \"mining.authorize\", "
        <<"\"id\":"<<this->msgId++
        <<", \"params\": [\""
            <<this->username<<"\", "
            <<"\""<<this->password
        <<"\"]}\n";
        this->tcpClient.send(ostr.str());
    }

    void checkRecv()
    {
        if(this->tcpClient.peek())
        {
            string data;
            this->tcpClient.getline(data);
            cout<<data<<endl;
            handleMessage(data);
        }
    }

    void handleMessage(string &data)
    {
        // cout<<data<<endl;

        //subscribe
        if(this->status == "subscribe")
        {
            Json::Reader reader;
            Json::Value root;
            if(reader.parse(data,root))
            {
                // int id = root["id"].asInt();
                // cout<<"id = "<<id<<endl;
                const Json::Value arrayObj = root["result"];
                string nonce1 = arrayObj[1].asString();
                cout<<"nonce1 = "<<nonce1<<endl;
                this->nonce1_size = nonce1.size() / 2;
                if(this->nonce2 == NULL)
                {
                    this->nonce2_size = 32 - this->nonce1_size;
                    this->nonce2 = new unsigned char [this->nonce2_size];
                    memset(this->nonce2,0,this->nonce2_size);
                }
                if(this->nonce1 != NULL)
                    delete this->nonce1;
                this->nonce1 = unhexlify(nonce1);
                // for (unsigned int i = 0; i < arrayObj.size(); i++)
                // {
                //     cout<<arrayObj[i].asString()<<endl;
                // }
                // string error = root["error"].asString();
                // cout<<"error = "<<error<<endl;
            }

            ///this->status = "authorize";
            // authorize make no sence
            this->status = "process";
        }
        else if(this->status == "authorize")
        {
            Json::Reader reader;
            Json::Value root;
            if(reader.parse(data,root))
            {
                // int id = root["id"].asInt();
                // cout<<"id = "<<id<<endl;
                bool result = root["result"].asBool();
                // cout<<result<<endl;
                string error = root["error"].asString();
                // cout<<"error = "<<error<<endl;
                if(!result)
                {
                    cout<<"Authorization failed: "<<error <<endl;
                }

                // cout << praenomen + " " + nomen + " " + cognomen
                //   << " was born in year " << born 
                //   << ", died in year " << died << endl;
            }

            this->status = "process";
        }
        else
        {
            Json::Reader reader;
            Json::Value root;
            if(reader.parse(data,root))
            {

                string method = root["method"].asString();
                cout<<"method = "<<method<<endl;
                if(method == "mining.set_target")
                {
                    // int id = root["id"].asInt();
                    // cout<<"id = "<<id<<endl;
                    const Json::Value arrayObj = root["params"];
                    string target = arrayObj[0].asString();
                    this->target = string2Bigint(target);
                    // cout<<"target = "<<target<<endl;
                    cout<<"set target  = "<<target<<endl;
                }
                else if(method == "mining.notify")
                {
                    // int id = root["id"].asInt();
                    // cout<<"id = "<<id<<endl;


                    const Json::Value arrayObj = root["params"];
                    string job_id = arrayObj[0].asString();
                    this->job_id = job_id;
                    string version = arrayObj[1].asString();
                    if(this->version != NULL)
                        delete this->version;
                    this->version = unhexlify(version);
                    string prev_hash = arrayObj[2].asString();
                    if(this->prev_hash != NULL)
                        delete this->prev_hash;
                    this->prev_hash = unhexlify(prev_hash);
                    string merkle_root = arrayObj[3].asString();
                    if(this->merkle_root != NULL)
                        delete this->merkle_root;
                    this->merkle_root = unhexlify(merkle_root);
                    string reserved = arrayObj[4].asString();
                    if(this->reserved != NULL)
                        delete this->reserved;
                    this->reserved = unhexlify(reserved);
                    string ntime = arrayObj[5].asString();
                    if(this->ntime != NULL)
                        delete this->ntime;
                    this->ntime = unhexlify(ntime);
                    string nbits = arrayObj[6].asString();
                    if(this->nbits != NULL)
                        delete this->nbits;
                    this->nbits = unhexlify(nbits);
                    bool clean_job = arrayObj[7].asBool();
                    this->clean_job = clean_job;

                    // cout<<"job_id = "<<job_id<<endl;
                    // cout<<"version = "<<version<<endl;
                    // cout<<"prev_hash = "<<prev_hash<<endl;
                    // cout<<"merkle_root = "<<merkle_root<<endl;
                    // cout<<"reserved = "<<reserved<<endl;
                    // cout<<"ntime = "<<ntime<<endl;
                    // cout<<"nbits = "<<nbits<<endl;
                    // cout<<"clean_job = "<<clean_job<<endl;
                    cout<<"Get new Job"<<endl;
                }
                else
                {
                    bool result = root["result"].asBool();
                    // cout<<result<<endl;
                    string error = root["error"].asString();
                    // cout<<"error = "<<error<<endl;
                    if(!result)
                    {
                        cout<<"Authorization failed: "<<error <<endl;
                    }
                    else
                    {
                        cout<<"Accept share"<<endl;
                    }
                }
            }
        }

    }

    void increase_nonce()
    {
        this->solnTimes++;
        this->hashRate = this->solnTimes / (float) (time(0)-this->startTime);
        // cout<<"HashRate = "<<this->hashRate<<" soln/s"<<endl;

        // 限制速率
        if(this->hashRate / 1000 > this->limitHashRate)
        {
            // cout<<"Hit"<<endl;
            usleep(10);
        }

        // nonce2 
        for(unsigned int i = this->nonce2_size - 1; i >= 0; i--)
        {
            if(this->nonce2[i] == 255)
            {
                this->nonce2[i] = 0;
            }
            else
            {
                this->nonce2[i] ++;
                break;
            }
        }

    }

    string getSolution()
    {
        // string result;
        // result.reserve(2694);

        //\xfd\x40\x05
        string tmp;
        tmp.reserve(21);
        for(unsigned int i = 0; i < 21; i++)
        {
            tmp[i] = table[rand()%16];
        }

        string result = "";
        result.push_back('f');
        result.push_back('d');
        result.push_back('4');
        result.push_back('0');
        result.push_back('0');
        result.push_back('5');
        for(int i =0; i < 128; i++)
        {
            for(int j = 0; j < 21; j++)
                result.push_back(tmp[j]);
        }
        // printf("result = %s\n",result.c_str());
        return result;

    }


    bool is_valid(const unsigned char * header, const unsigned char * exp_solution, Dodecahedron::Bigint target)
    {

        // unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
        static unsigned char input[1487]; // 140 + 1347 =  1487

        memcpy(input,header,140);
        memcpy(input+140,exp_solution,1347);

        // for(int i =0; i < 20; i++)
        // {
        //     cout<<int(input[i])<<endl;
        // }

        unsigned char result0[SHA256_DIGEST_LENGTH] = {0};
        unsigned char result[SHA256_DIGEST_LENGTH] = {0};

        SHA256(input,1487,result0);
        SHA256(result0,SHA256_DIGEST_LENGTH,result);

        // for(int i = 0; i < 32; i++)
        // {
        //     cout<<int(result[i])<<endl;
        // }

        Dodecahedron::Bigint hashInt = unsignedCharArray2Bigint(result,32);
        // cout<<hashInt<<endl;
        // cout<<target<<endl;

        return hashInt < target;
        // return int.from_bytes(hash, 'little') < target
    }


    void minering()
    {

        this->increase_nonce();

        // cout<<"nonce2 -----> "<<hexlify(this->nonce2,24)<<endl;

        // unsigned char * header = new unsigned char[140];
        unsigned char header[140];// = new unsigned char[140];

        if(this->version == NULL)
            return;
        // cout<<hexlify(this->version,4)<<endl;
        memcpy(header+0,this->version,4);
        memcpy(header+4,this->prev_hash,32);
        memcpy(header+4+32,this->merkle_root,32);
        memcpy(header+4+32+32,this->reserved,32);
        memcpy(header+4+32+32+32,this->ntime,4);
        memcpy(header+4+32+32+32+4,this->nbits,4);
        memcpy(header+4+32+32+32+4+4,this->nonce1,this->nonce1_size);
        memcpy(header+4+32+32+32+4+4+this->nonce1_size,this->nonce2,this->nonce2_size);


        // string header = this->version + this->prev_hash + this->merkle_root + this->reserved + this->ntime + this->nbits + this->nonce1 + this->nonce2;

        string exp_solution = this->getSolution();

        unsigned char * solution = unhexlify(exp_solution.c_str(), 1347 * 2);

        if(this->is_valid(header, solution ,this->target))
        {
            cout<<"Found One !"<<endl;
            cout<<"HashRate = "<<this->hashRate / 1000 <<" Ksoln/s"<<endl;
            ostringstream ostr;
            ostr << "{\"id\": "
            <<this->msgId<<", \"method\": \"mining.submit\", \"params\": [\""
            <<this->username<<"\", \""
            <<this->job_id<<"\", \""
            <<hexlify(this->ntime,4)<<"\", \""
            <<hexlify(this->nonce2,this->nonce2_size)
            <<"\", \""
            <<exp_solution
            <<"\"]}\n";
            this->tcpClient.send(ostr.str());
            times=times+1;
            if(times>max_times)
            {
                printf("done!");
                exit(0);
            }


            // send
            // {"id": 4, "params": ["PMTPTEAzrsCnrn9YvFmJ9y3FmJNuMaTU6M.minerf", "42a0a", "3a2bec5a", "03000000000000000000000000000000000000000000001e", "fd4005f2..."], "method": "mining.submit"}
            // {"id": 4, "method": "mining.submit", "params": ["WORKER_NAME", "JOB_ID", "TIME", "NONCE_2", "EQUIHASH_SOLUTION"]}\n

        }

        // 释放内存
        delete solution;

    }
};


int main(int argc, char **argv)
{

    // test();


    times=0;
    Stratum stratum(argv[3], atoi(argv[4]),
                        argv[1], argv[2]);
    if(argc == 6)
    {
        stratum.limitHashRate = atof(argv[5]);
        cout<<"set limit hash rate is "<< atof(argv[5]) <<endl;
    }

    while(stratum.isRunning)
    {
        try{
            if(!stratum.isConnected)
            {
                stratum.connect();
                stratum.subscribe();
                stratum.authorize();
            }

            stratum.checkRecv();
            if(stratum.status == "process")
            {
                stratum.minering();
            }
            // usleep(100000);
        }
        catch (exception& e)  
        {  
            cout << "Standard exception: " << e.what() << endl; 
        }
    }


    return 0;
}






