#include <iostream>
#include <random>
#include <vector>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>

#include "json.hpp"
#include <openssl/sha.h>
#include <openssl/hmac.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define CLOSESOCKET closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define CLOSESOCKET close
#endif



using namespace std;
using json = nlohmann::json;

const int nDelay = 3; //密钥延迟披露时间，这里delay应该为2，但是打包数据包时为了将index和密钥号统一，循环从i=1开始，所以将delay设置为3
const int nTotalKey = 3001;

const int N_GROUP_SIZE = 300;
const int N_DECTECING = 5;

string strTESLAInitKey = "Hello World";
string strSendmessage = "TESLA Protocol";
string strContext = "gen_mac";

//TESLA协议数据包结构体
struct TeslaProtocolPacket {
    string strSenderId;
    int nIndex;
    string strMessage;
    //string strMac;
    string strDisclosedKey;
    vector<string> vecSamdTau;

    json to_json() const {
        return json{ {"strSenderId", strSenderId}, {"nIndex", nIndex}, 
            {"strMessage", strMessage}, /*{"strMac", strMac},*/
            {"strDisclosedKey", strDisclosedKey} , {"vecSamdTau", vecSamdTau} };
    }
};

//TESLA协议初始阶段，认证信道sender向receiver发送的参数
struct TeslaInitPacket {
    string strSenderId;
    string strCommitmentKey; //K0
    string strZeroKey;       //未披露密钥时的填充密钥
    int nTotalKeys;        //N
    int nIntervalLengthMs;   //时间间隔
    int nDisclosureDelay;  //密钥披露延迟delay
    string strF_Definition;  //密钥生成函数F（sha256）
    string strFprime_definition; //为随机函数F‘（sha256||context）
    string strContext;
    long long lSenderTimestamp;//sender当前时间

    // 将结构体转为 JSON
    json to_json() const {
        return json{
                {"strSenderId",strSenderId},
                {"strCommitmentKey", strCommitmentKey},
                {"strZeroKey", strZeroKey},
                {"nTotalKeys", nTotalKeys},
                {"nIntervalLengthMs", nIntervalLengthMs},
                {"nDisclosureDelay", nDisclosureDelay},
                {"strF_Definition", strF_Definition},
                {"strFprime_definition", strFprime_definition},
                {"strContext", strContext},
                {"lSenderTimestamp", lSenderTimestamp} };
    }
};

void print_hash(string p) {
    for (unsigned int i = 0; i < p.size(); ++i) {
        printf("%02x", static_cast<unsigned char>(p[i]));  // 小写 16 进制格式
    }
}

void print_packet(const TeslaProtocolPacket& ppacket) {
    cout << "[Packet : Index " << ppacket.nIndex << " | Message = "
        << ppacket.strMessage << /*" | MAC = " << ppacket.strMac <<*/ " | Key = "
        << ppacket.strDisclosedKey << "]" << endl;
}

void printVector(const vector<string>& vec) {
    for (const auto& s : vec) {
        cout << s << endl;
    }
}

//将二进制数据转化为可读的字符串
string strToHexString(const unsigned char* data, size_t nlength) {
    static const char hex_chars[] = "0123456789abcdef";
    string strResult;
    strResult.reserve(nlength * 2);

    for (size_t i = 0; i < nlength; ++i) {
        strResult.push_back(hex_chars[(data[i] >> 4) & 0xF]);
        strResult.push_back(hex_chars[data[i] & 0xF]);
    }
    return strResult;
}

//sender：生成SenderID
string strGenerateSenderId() {
    // 获取当前时间戳（毫秒）
    auto now = chrono::system_clock::now();
    auto millis = chrono::duration_cast<chrono::milliseconds>(
        now.time_since_epoch()).count();

    // 随机数生成器（用于增加 ID 唯一性）
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 0xFFFFFF);

    // 组合时间戳和随机数生成字符串 ID
    stringstream ss;
    ss << "sender_"
        << hex << uppercase << millis
        << "_"
        << setw(6) << setfill('0') << dis(gen);

    return ss.str();
}

//sender：利用sha256计算单向链
vector<string> vec_strGenerateKeyChain(string strInitKey) {
    vector<string> vec_strKeyChain(nTotalKey);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)strInitKey.c_str(), strInitKey.size(), hash);
    vec_strKeyChain[nTotalKey - 1] = strToHexString(hash, SHA256_DIGEST_LENGTH);

    for (int i = nTotalKey - 2; i >= 0; i--) {
        SHA256((unsigned char*)vec_strKeyChain[i + 1].c_str(), vec_strKeyChain[i + 1].size(), hash);
        vec_strKeyChain[i] = strToHexString(hash, SHA256_DIGEST_LENGTH);
    }
    return vec_strKeyChain;
}

//sender，初始阶段发送给receiver：伪随机函数F‘，作用于已生成的单向链中的密钥，生成新的mac密钥，达到避免密钥重用的目的
string strF_Prime(const string& strKi, const string& strContext) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    string strInput = strKi + strContext; // 加入上下文防止重用

    SHA256(reinterpret_cast<const unsigned char*>(strInput.c_str()), strInput.size(), hash);
    return string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

//sender，初始阶段发送给receiver：使用F′生成MAC密钥，并对message进行HMAC-SHA256计算
string strComputeMAC(const string& strMessage, const string& strKi, const string& strContext) {
    string strMacKey = strF_Prime(strKi, strContext);

    unsigned char result[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;

    HMAC(EVP_sha256(),
        reinterpret_cast<const unsigned char*>(strMacKey.data()), strMacKey.size(),
        reinterpret_cast<const unsigned char*>(strMessage.data()), strMessage.size(),
        result, &len);

    return strToHexString(result, len);
}

//利用UDP交换数据，以下是端到端和广播两种通信方式
bool bSendInitPacket_P2P(const TeslaInitPacket& packet, const string& strIP = "192.168.1.100", int port = 8888) {
    socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cout << "Send Init Packet Socket Create Failed!" << endl;
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

#ifdef _WIN32
    inet_pton(AF_INET, strIP.c_str(), &addr.sin_addr);
#else
    inet_pton(AF_INET, strIP.c_str(), &addr.sin_addr);
#endif

    string data = packet.to_json().dump();
    sendto(sockfd, data.c_str(), data.size(), 0, (sockaddr*)&addr, sizeof(addr));
    cout << "[Sender] Packet sent to " << strIP << ":" << port << endl;

    CLOSESOCKET(sockfd);

    return true;
}

bool bSendInitPacket_Broadcast(const TeslaInitPacket& packet, int port = 9999) {
    socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cout << "Send Init Packet Socket Create Failed!" << endl;
        return false;
    }
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&optval, sizeof(optval));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_BROADCAST;

    string data = packet.to_json().dump();
    sendto(sockfd, data.c_str(), data.size(), 0, (sockaddr*)&addr, sizeof(addr));
    cout << "[Sender:BROADCAST] Packet broadcasted on port " << port << endl;

    CLOSESOCKET(sockfd);

    return true;
}

//通过UDP发送协议数据包，以下是P2P和广播两种方式
bool bSendProtocolPacket_P2P(const TeslaProtocolPacket& packet, const string& strIP = "192.168.1.100", int port = 8888) {
    socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cout << "Send Protocol Packet Socket Create Failed!" << endl;
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
#ifdef _WIN32
    inet_pton(AF_INET, strIP.c_str(), &addr.sin_addr);
#else
    inet_pton(AF_INET, strIP.c_str(), &addr.sin_addr);
#endif
    std::string data = packet.to_json().dump();
    sendto(sockfd, data.c_str(), data.size(), 0, (sockaddr*)&addr, sizeof(addr));

    CLOSESOCKET(sockfd);

    return true;
}

bool bSendProtocolPacket_Broadcast(const TeslaProtocolPacket& packet, int port = 7777) {
    socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cout << "Send Protocol Packet Socket Create Failed!" << endl;
        return false;
    }
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&optval, sizeof(optval));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_BROADCAST;

    string data = packet.to_json().dump();
    sendto(sockfd, data.c_str(), data.size(), 0, (sockaddr*)&addr, sizeof(addr));
    cout << "[Sender:BROADCAST] Packet broadcasted on port " << port << endl << endl;

    CLOSESOCKET(sockfd);

    return true;
}

//获取当前时间的函数，用于发送sender在认证信道第一次通信的时间，receiver利用其计算Δ
long long currentTimeMillis() {
    return chrono::duration_cast<chrono::milliseconds>(
        chrono::system_clock::now().time_since_epoch()).count();
}


//待发送的数据包类数组
vector<TeslaProtocolPacket> vecTeslaQueue(nTotalKey + nDelay - 1);

//--------------------------------------
// 判断素数 / 找到 >= x 的最小素数
//--------------------------------------

bool IsPrime(int x)
{
    if (x <= 1) return false;
    if (x == 2 || x == 3) return true;
    if ((x & 1) == 0) return false;
    int i = 3;
    while ((long long)i * (long long)i <= (long long)x)
    {
        if (x % i == 0) return false;
        i += 2;
    }
    return true;
}

int NextPrime(int x)
{
    if (x <= 2) return 2;
    int n = x;
    if ((n & 1) == 0) n += 1;
    while (!IsPrime(n))
    {
        n += 2;
    }
    return n;
}

//--------------------------------------
// 计算最小 k，使 q^k >= N（用整数累乘避免浮点）
//--------------------------------------
int MinK_Pow_q_ge_N(int N, int q, int k_max)
{
    int k = 0;
    long long cur = 1;
    while (cur < (long long)N && k < k_max)
    {
        cur = cur * (long long)q;
        ++k;
    }
    if (cur >= (long long)N && k > 0) return k;
    // 表示失败（在给定 k_max 范围内找不到）
    return -1;
}

//--------------------------------------
// 幂: base^exp mod mod
//--------------------------------------
int PowModInt(int base, int exp, int mod)
{
    long long result = 1;
    long long b = base % mod;
    int e = exp;
    while (e > 0)
    {
        if ((e & 1) != 0)
        {
            result = (result * b) % mod;
        }
        b = (b * b) % mod;
        e >>= 1;
    }
    return (int)result;
}

//--------------------------------------
// KS 矩阵结构
//--------------------------------------
struct KSMatrix
{
    int N;
    int d;
    int q;
    int n;
    int k;
    int u;
    vector< vector<int> > G;  // u x N 0/1 矩阵
};

static KSMatrix g_SamdKSGt;
static bool g_bSmadGtInited = false;

//--------------------------------------
// 在 KS+RS 族中搜索 q,n,k，使 u=n*q 尽可能小
//--------------------------------------
void FindBestParamsForKSRS(int N, int d,
    int& best_q, int& best_n,
    int& best_k, int& best_u)
{
    int q_start = 2 * d + 1;
    if (q_start < 2) q_start = 2;
    int q = NextPrime(q_start);

    int globalBestU = -1;
    int globalBestQ = -1;
    int globalBestN = -1;
    int globalBestK = -1;

    // 设一个安全上界（视需求可调）
    int q_max = 10000;
    int k_max = 16; // 对 N 在 100~1000、q 不太大时足够

    while (q <= q_max)
    {
        // 对当前 q，先找最小 k 满足 q^k >= N
        int k = MinK_Pow_q_ge_N(N, q, k_max);
        if (k != -1)
        {
            int n = k + 2 * d;
            // RS 码长度要求 n <= q
            if (n <= q)
            {
                int u = n * q;
                if (globalBestU < 0 || u < globalBestU)
                {
                    globalBestU = u;
                    globalBestQ = q;
                    globalBestN = n;
                    globalBestK = k;
                }
            }
        }

        // 可以加个剪枝：如果 q 已经远大于 globalBestU，也可以 break
        // 这里为了简单就不写剪枝了
        q = NextPrime(q + 1);
    }

    if (globalBestU < 0)
    {
        // 没找到合法参数（几乎不可能出现于你当前 N,d 范围），
        // 这里简单退回到 q = NextPrime(max(2d+1, N)，n=q，k=1 的方案）
        int lower_q = 2 * d + 1;
        if (lower_q < N) lower_q = N;
        int fallback_q = NextPrime(lower_q);
        int fallback_k = 1;
        int fallback_n = fallback_k + 2 * d;
        if (fallback_n > fallback_q) fallback_n = fallback_q;
        int fallback_u = fallback_n * fallback_q;

        best_q = fallback_q;
        best_n = fallback_n;
        best_k = fallback_k;
        best_u = fallback_u;
        return;
    }

    best_q = globalBestQ;
    best_n = globalBestN;
    best_k = globalBestK;
    best_u = globalBestU;
}

//--------------------------------------
// 按最优参数构造 KS+RS 二进制矩阵
//--------------------------------------
void BuildOptimizedKSMatrix()
{
    
    g_SamdKSGt.N = N_GROUP_SIZE;
    g_SamdKSGt.d = N_DECTECING;

    int q, n, k, u;
    FindBestParamsForKSRS(N_GROUP_SIZE, N_DECTECING, q, n, k, u);

    g_SamdKSGt.q = q;
    g_SamdKSGt.n = n;
    g_SamdKSGt.k = k;
    g_SamdKSGt.u = u;

    // 构造 q 元 RS 码字：rs_code[i][j], i=0..n-1, j=0..N-1
    vector< vector<int> > rs_code;
    rs_code.assign(g_SamdKSGt.n, vector<int>(g_SamdKSGt.N, 0));

    int j = 0;
    int i = 0;
    int t = 0;

    j = 0;
    while (j < g_SamdKSGt.N)
    {
        // j 的 q 进制展开到 a[0..k-1]
        int tmp = j;
        int a[64];
        t = 0;
        while (t < 64)
        {
            a[t] = 0;
            ++t;
        }
        t = 0;
        while (t < g_SamdKSGt.k)
        {
            a[t] = tmp % g_SamdKSGt.q;
            tmp = tmp / g_SamdKSGt.q;
            ++t;
        }

        // 在 x=0..n-1 上评估 P_j(x)
        i = 0;
        while (i < g_SamdKSGt.n)
        {
            long long val = 0;
            int x = i;
            t = 0;
            while (t < g_SamdKSGt.k)
            {
                int x_pow_t = PowModInt(x, t, g_SamdKSGt.q);
                long long term = (long long)a[t] * (long long)x_pow_t;
                val += term;
                val %= g_SamdKSGt.q;
                ++t;
            }
            rs_code[i][j] = (int)val;
            ++i;
        }

        ++j;
    }

    // KS 映射：得到 u x N 的 0/1 矩阵
    g_SamdKSGt.G.assign(g_SamdKSGt.u, vector<int>(g_SamdKSGt.N, 0));

    i = 0;
    while (i < g_SamdKSGt.n)
    {
        j = 0;
        while (j < g_SamdKSGt.N)
        {
            int s = rs_code[i][j];  // 0..q-1
            int row = i * g_SamdKSGt.q + s;
            g_SamdKSGt.G[row][j] = 1;
            ++j;
        }
        ++i;
    }

    g_bSmadGtInited = true;
}

void EnsureSamdGtMatrix()
{
    if (!g_bSmadGtInited)
    {
        BuildOptimizedKSMatrix();
    }
}

static string strToHex(const string& strInput) 
{
    static const char* hex_digits = "0123456789abcdef";
    string strOutput;
    strOutput.reserve(strInput.size() * 2);
    for (unsigned char c : strInput) {
        strOutput.push_back(hex_digits[(c >> 4) & 0x0F]);
        strOutput.push_back(hex_digits[c & 0x0F]);
    }
    return strOutput;
}

string strHashFunc(const string& strData) 
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, reinterpret_cast<const unsigned char*>(strData.data()), strData.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &len) != 1 || len != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

string strSamdHashFromMacList(const vector<string>& vecMACs)
{
    string strBuffer;
    int n = (int)vecMACs.size();
    for (int i = 0; i < n; i++)
    {
        strBuffer.push_back((char)0x01);
        strBuffer.append(vecMACs[i]);
    }

    return strToHex(strHashFunc(strBuffer));
}

void Samd_DSeqAgg(const vector<string>& vecMACs, vector<string>& vecTauOut)
{
    EnsureSamdGtMatrix();

    int N = (int)vecMACs.size();
    int u = g_SamdKSGt.u;

    vecTauOut.clear();
    vecTauOut.resize(u);

    for (int i = 0; i < u; i++)
    {
        vector<string> vecTemp;
        for (int j = 0; j < N; j++)
        {
            if (g_SamdKSGt.G[i][j] == 1)
            {
                vecTemp.push_back(vecMACs[i]);
            }
        }
        
        if (vecTemp.empty())
        {
            vecTauOut[i].clear();
        }
        else
        {
            vecTauOut[i] = strSamdHashFromMacList(vecTemp);
        }
    }
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed!\n";
        return -1;
    }
#endif

    string strKey0;//单向链计算的最后一个密钥，实际调用的第一个密钥的前一个密钥，在通信的最初阶段发送给接收方用于验证后续披露的密钥
    string strKeyObeject;//当前使用的密钥
    string strMessageMAC;//存储message Mac的变量
    //string strKeyNext;//存储当前密钥的下一个密钥，用于验证
    //string zero =strGenerateRandomKey(32);//用于填充未披露密钥

    int nCount = 0;
    vector<string> vecWaitForDSeqAgg;
    vector<string> vecTau;
    vector<string> vecMac;


    vector<string> One_Way_Chain = vec_strGenerateKeyChain(strTESLAInitKey);//密钥链
    strKey0 = One_Way_Chain[0];
    cout << "Key0 = " << strKey0 << endl;
    // for (int i = 0; i < One_Way_Chain.size(); i++) {
    //     cout << "K[" << i << "]" << One_Way_Chain[i] << endl;
    // }

    /*已完成
     *TESLA协议初始阶段，建立认证信道，发送方向接收方提供：
     *1、单项密钥的承诺值K0，用于接收方后续接收到TESLA数据包后验证延迟披露的密钥
     *2、单向函数F和伪随机F‘的定义，用于验证MessageMAC和计算密钥
     *3、时间间隔计划，包括：时间间隔长度、起始时间、当前时间间隔的索引、单向链的长度。用于确定密钥延迟披露的时间确认发送方时间上界判断是否是有效的数据包
    */
    long long currentTime = currentTimeMillis();
    cout << "Current Time = " << currentTime << endl;
    string strSenderId = strGenerateSenderId();
    TeslaInitPacket packet{
        strSenderId, strKey0, "zero", nTotalKey, 1000, nDelay, "SHA256", "SHA256(Ki||context)", strContext, currentTime
    };
    //sendInitPacket_P2P(packet, "10.8.12.84", 8888);//ip要替换为接收方ip
    bSendInitPacket_Broadcast(packet);
    bSendInitPacket_Broadcast(packet, 8888);
    this_thread::sleep_for(chrono::seconds(1));


    //将数据包打包完成，为了将所有密钥披露，循环次数应加上密钥延迟披露的时间，delay实际为2，但为保证index和密钥号统一所以设置为3，所以这里有-1操作
    for (int i = 1; i < nTotalKey + nDelay - 1; ++i) {

        vecTeslaQueue[i].nIndex = i;
        vecTeslaQueue[i].strSenderId = strSenderId;
        

        if (i < nTotalKey) {
            if (i < nDelay) {//从第三个数据包开始披露1号密钥，0号密钥不使用，作为承诺值发送给receiver
                vecTeslaQueue[i].strDisclosedKey = "zero";
            }
            else {
                vecTeslaQueue[i].strDisclosedKey = One_Way_Chain[i - 2];
            }

            strKeyObeject = One_Way_Chain[i];
            strMessageMAC = strComputeMAC(strSendmessage + to_string(i), strKeyObeject, strContext + to_string(i));
            vecMac.push_back(strMessageMAC);
            vecWaitForDSeqAgg.push_back(strMessageMAC);
            nCount++;

            if (nCount == N_GROUP_SIZE)
            {
                Samd_DSeqAgg(vecWaitForDSeqAgg, vecTau);
                vecWaitForDSeqAgg.clear();
                nCount = 0;
                vecTeslaQueue[i].vecSamdTau = vecTau;
            }

            
            //vecTeslaQueue[i].strMac = strMessageMAC;
            //print_hash(MessageMAC);
            //cout << endl;

            vecTeslaQueue[i].strMessage = strSendmessage + to_string(i);
        }
        else {
            vecTeslaQueue[i].strDisclosedKey = One_Way_Chain[i - 2];
            vecTeslaQueue[i].strMessage = "";
            //vecTeslaQueue[i].strMac = "";
        }
        print_packet(vecTeslaQueue[i]);

        bSendProtocolPacket_Broadcast(vecTeslaQueue[i]);
        bSendProtocolPacket_Broadcast(vecTeslaQueue[i], 6666);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        
    }

    /*发送数据包，因为密钥延迟披露的原因，每间隔一秒发送一次数据包 √
     *在发送数据包之前需要发送sender的当前时间，receiver通  过这一阶段确认通信的时延，以便在后续接收的过程中计算sender的时间上界 √
     *发送功能仍需要考虑是在打包时完成，还是将所有数据包封装好之后发送 √
     */

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}