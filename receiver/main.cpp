#include <iostream>
#include <random>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <time.h>

#include "json.hpp"
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <thread>
#include <mutex>
#include <deque>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <condition_variable>
#include <atomic>
// 是否启用线程化接收（0 = 原有 while/recv 逻辑；1 = 启用监听线程 + 线程池）
#ifndef USE_THREADED_RECEIVER
#define USE_THREADED_RECEIVER 1
#endif


#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
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

#ifdef _WIN32
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#endif


using namespace std;
using json = nlohmann::json;
const int N_BASE_SLOT = 1; // TESLA 报文从 1 开始编号
const int N_GROUP_SIZE = 100;
const int N_DECTECING = 1;

// ===== ADDED: 每个 sender 独立的接收端上下文 =====
struct SReceiverContext {
    // TESLA 参数
    string strKey0;          // K0
    int nTotalKeys = 0;           // N
    int nDelay = 0;               // d
    int nIntervalLengthMs = 0;    // Tint
    long long lDeltaMs = 0;       // 估计的时间偏移Δ
    string strContext;       // F' 的上下文

    // 缓冲与统计
    vector<string> vecReceiveMessageBuffer;     // receiveMessageBuffer
    vector<string> vecReceiveMessageKeyBuffer;     // receiveMessageKEYBuffer
    vector<string> vecSamdTau;
    vector<string> vecRecvMsgWithoutKey;

    int nValidKeyCnt = 0;
    int nDelayMemoryKeyCnt = 0;
    bool bIsLostPacket = false;
    int nLastKeyIndex = 0;
    int nGroupCnt = 0;
    int nRecvTauIndex = 0;
    int nLastTauIndex = 0;

    // 分组聚合需要的时间戳等（可选）
    //std::chrono::steady_clock::time_point tpLastTouch = std::chrono::steady_clock::now();
};

struct TeslaProtocolPacket {
    string strSenderId;
    int nIndex;
    string strMessage;
    string strDisclosedKey;
    vector<string> vecSamdTau;

    static TeslaProtocolPacket from_json(const json& j) {
        return { j["strSenderId"], j["nIndex"], j["strMessage"], j["strDisclosedKey"], j["vecSamdTau"]};
    }
};

struct TeslaInitPacket {
    string strSenderId;     //发送方ID
    string strCommitmentKey; //K0
    string strZeroKey;       //未披露密钥时的填充密钥
    int nTotalKeys;        //N
    int nIntervalLengthMs;   //时间间隔
    int nDisclosureDelay;  //密钥披露延迟delay
    string strF_Definition;  //密钥生成函数F（sha256）
    string strFprime_definition; //为随机函数F‘（sha256||context）
    string strContext;
    long long lSenderTimestamp;//sender当前时间

    static TeslaInitPacket from_json(const json& j) {
        return {
            j["strSenderId"], j["strCommitmentKey"], j["strZeroKey"], j["nTotalKeys"],
            j["nIntervalLengthMs"], j["nDisclosureDelay"], j["strF_Definition"], j["strFprime_definition"],
            j["strContext"], j["lSenderTimestamp"]
        };
    }
};

// 串行通道：同一 sender 的任务在该通道内串行执行
struct SSenderStrand {
    mutex mtxQ;                                          //互斥锁
    deque<function<void()>> dqTasks;                     //任务队列
    bool bScheduled = false;                              // 是否已派发到线程池执行
    atomic<long long> llLastActiveMs{ 0 };             // 最近活动
    int nPriority = 0;                                    // 可选：优先级
    size_t nDroppedTasks = 0;                             // 超限丢弃计数
};

//fixed-size thread pool
class CThreadPool {
public:
    explicit CThreadPool(int nWorkers) : bStop(false) {
        if (nWorkers <= 0) nWorkers = 2;
        vecWorkers.reserve(nWorkers);
        for (int i = 0; i < nWorkers; ++i) {
            vecWorkers.emplace_back([this] {
                for (;;)
                {
                    function<void()> fnTask;
                    {   // 取任务
                        unique_lock<mutex> lk(mtxQ);
                        cvQ.wait(lk, [this] { return bStop || !dqTasks.empty(); });
                        if (bStop && dqTasks.empty())
                        {
                            return;
                        }
                        fnTask = move(dqTasks.front());
                        dqTasks.pop_front();
                    }
                    // 执行
                    try
                    {
                        fnTask();
                    }
                    catch (...) {}
                }
                });
        }
    }
    ~CThreadPool() {
        { lock_guard<mutex> lk(mtxQ); bStop = true; }
        cvQ.notify_all();
        for (auto& t : vecWorkers) if (t.joinable()) t.join();
    }
    void Enqueue(function<void()> fn) {
        { lock_guard<mutex> lk(mtxQ); dqTasks.emplace_back(move(fn)); }
        cvQ.notify_one();
    }
private:
    vector<thread> vecWorkers;
    deque<function<void()>> dqTasks;
    mutex mtxQ;
    condition_variable cvQ;
    bool bStop;
};

long long lCurrentTimeMillis()
{
    return chrono::duration_cast<chrono::milliseconds>(
        chrono::system_clock::now().time_since_epoch()).count();
}

int nComputeSenderUpperBoundInterval(long long receiverTimeMs, int intervalLengthMs, int deltaMs)
{
    return (receiverTimeMs + deltaMs) / intervalLengthMs;
}

long long lEstimateTimeOffset(const TeslaInitPacket& initPkt)
{
    long long recvTime = lCurrentTimeMillis();
    long long delta = recvTime - initPkt.lSenderTimestamp;
    cout << "[TIME SYNC] Sender time = " << initPkt.lSenderTimestamp
        << ", Receiver time = " << recvTime
        << ", Estimated delta = " << delta << " ms" << endl;
    return delta;
}

static unordered_map<string, shared_ptr<SSenderStrand>> g_mapStrands; //所有已知sender的串行通道map
static mutex g_mtxStrands;

static unordered_set<string> g_setKnownSenders; //已知的sender的表，已经收到过该sender的init包了
static mutex g_mtxKnown;

static unordered_map<string, shared_ptr<SReceiverContext>> g_mapCtx;// 根据sender_id创建该sender上下文的map
static mutex g_mtxCtx;

static unique_ptr<CThreadPool> g_pThreadPool;
static atomic<bool> g_bRunning{ false };
static int g_nWorkerThreads = 10;          //线程池大小
static const size_t N_MAX_STRAND_QUEUE = 2048;  // 每个 sender 的任务队列上限
static const long long LL_IDLE_TTL_MS = 60'000; // 空闲回收阈值

// 获取或创建某 sender 的上下文
static shared_ptr<SReceiverContext> GetOrCreateCtx(const string& strSenderId) {
    lock_guard<mutex> g(g_mtxCtx);
    auto it = g_mapCtx.find(strSenderId);
    if (it != g_mapCtx.end()) return it->second;
    auto p = make_shared<SReceiverContext>();
    g_mapCtx.emplace(strSenderId, p);
    return p;
}

/*
* PostDrainLocked_ 和 PostToSender 是多发送端并发处理场景中，用于确保“单发送端内串行执行，多个发送端间并行执行”的关键组件
* 在一个接收端中，如果多个发送端（不同 sender_id）发送数据包到同一接收端：
        不同的 sender_id 应该并行处理（提高吞吐）。
        同一个 sender_id 的数据要保证顺序不乱（避免状态混乱）。
  这就是 “per-sender 串行通道（strand）” 的设计意图：
        针对每个发送端，我们设立一个独立的 FIFO 队列，保证它的任务是串行处理；
        同一时刻，不同 sender 的任务可以在不同线程上并行运行。

*PostToSender作用：将一个任务投递到对应 sender_id 的任务队列中。如果队列之前是空且未运行，则自动触发该队列执行。
*详细流程：
    1、找到或创建一个 sender 的串行队列（SSenderStrand）
        通过全局 g_mapStrands[strSenderId] 获取对应的上下文（包含队列、调度状态等）。
    2、向对应 sender 的任务队列中追加任务（FIFO）
        所有任务都用 std::function<void()> 包装，可以绑定任意代码（如 TESLA 包解码、密钥验证等）。
    3、判断是否需要调度运行队列任务
        如果队列之前是空的，且这个 sender 当前没有挂起执行，那么立即安排线程池执行它。

*PostDrainLocked_作用：在后台线程中顺序执行该 sender_id 的所有任务。执行完队列为空后自动退出，不占资源。
*执行逻辑： 
    1、设置标记 bScheduled=true，表示当前 sender 正在执行任务。
    2、投递一个线程池任务来“Drain”任务队列
        这个线程执行一个无限循环：
            从队列头取一个任务（保证 FIFO 顺序）
            执行任务函数 fn()
            继续取下一个，直到队列变空退出
    3、任务函数 fn() 是由你封装的处理逻辑
        比如：TESLA 单包处理、密钥验证、聚合验证、状态更新等。
    4、执行完队列后，清除 bScheduled 标志
        表示该 sender 当前没有任务在跑，后续新的任务可再次触发执行。
*/

// 把 drain(串行耗尽)任务丢给线程池
static void PostDrainLocked_(const shared_ptr<SSenderStrand>& pStrand) {
    pStrand->bScheduled = true;
    g_pThreadPool->Enqueue([pStrand] {
        for (;;) {
            function<void()> fn;
            {
                lock_guard<mutex> lk(pStrand->mtxQ);
                if (pStrand->dqTasks.empty()) { pStrand->bScheduled = false; break; }
                fn = move(pStrand->dqTasks.front());
                pStrand->dqTasks.pop_front();
            }
            try 
            { 
                fn(); 
            }
            catch (...) {}
            pStrand->llLastActiveMs = lCurrentTimeMillis();
        }
        });
}

// 投递任务到某个 sender 的串行通道
static void PostToSender(const string& strSenderId, function<void()> fnTask) {
    shared_ptr<SSenderStrand> p;
    {
        lock_guard<mutex> g(g_mtxStrands);
        auto it = g_mapStrands.find(strSenderId);
        if (it == g_mapStrands.end()) 
        {
            p = make_shared<SSenderStrand>();
            p->llLastActiveMs = lCurrentTimeMillis();
            g_mapStrands.emplace(strSenderId, p);
        }
        else 
        {
            p = it->second;
        }
    }
    bool bNeedSchedule = false;
    {
        lock_guard<mutex> lk(p->mtxQ);
        if (p->dqTasks.size() >= N_MAX_STRAND_QUEUE) { p->nDroppedTasks++; return; }
        p->dqTasks.emplace_back(move(fnTask));
        if (!p->bScheduled) bNeedSchedule = true;
    }
    if (bNeedSchedule) PostDrainLocked_(p);
}

// 空闲回收：无任务且长时间无活动的 strand 被回收
static void GcIdleStrands() {
    const long long now = lCurrentTimeMillis();
    vector<string> vecRemove;
    {
        lock_guard<mutex> g(g_mtxStrands);
        for (auto& kv : g_mapStrands) {
            auto& p = kv.second;
            lock_guard<mutex> lk(p->mtxQ);
            if (!p->bScheduled && p->dqTasks.empty() && (now - p->llLastActiveMs.load()) > LL_IDLE_TTL_MS) {
                vecRemove.push_back(kv.first);
            }
        }
        for (auto& id : vecRemove) g_mapStrands.erase(id);
    }
}
// ===== END ADDED

//已知 sender 表（收到 Init 才算“已知”）
static inline void MarkSenderKnown(const string& strSenderId) {
    lock_guard<mutex> g(g_mtxKnown);
    g_setKnownSenders.insert(strSenderId);
}

static inline bool IsSenderKnown(const string& strSenderId) {
    lock_guard<mutex> g(g_mtxKnown);
    return g_setKnownSenders.count(strSenderId) > 0;
}

//只确保某 sender 的 strand 存在（不投任务）如果没有就创建
static void EnsureStrandExists(const string& strSenderId) {
    lock_guard<mutex> g(g_mtxStrands);
    if (g_mapStrands.find(strSenderId) == g_mapStrands.end()) 
    {
        auto p = make_shared<SSenderStrand>();
        p->llLastActiveMs = lCurrentTimeMillis();
        g_mapStrands.emplace(strSenderId, move(p));
    }
}

void print_hash(string p) 
{
    for (unsigned int i = 0; i < p.size(); ++i) {
        printf("%02x", static_cast<unsigned char>(p[i]));  // 小写 16 进制格式
    }
}

void print_packet(const TeslaProtocolPacket& ppacket) 
{
    cout << "[Packet : Index " << ppacket.nIndex << " | Message = "
        << ppacket.strMessage/*<< " | MAC = " << ppacket.strMac*/  << " | Key = "
        << ppacket.strDisclosedKey << "]" << endl << endl;
}

string strToHexString(const unsigned char* data, size_t nlength) 
{
    static const char hex_chars[] = "0123456789abcdef";
    string strResult;
    strResult.reserve(nlength * 2);

    for (size_t i = 0; i < nlength; ++i) 
    {
        strResult.push_back(hex_chars[(data[i] >> 4) & 0xF]);
        strResult.push_back(hex_chars[data[i] & 0xF]);
    }
    return strResult;
}

string strF_Prime(const string& strKi, const string& strContext) 
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    string strInput = strKi + strContext; // 加入上下文防止重用

    SHA256(reinterpret_cast<const unsigned char*>(strInput.c_str()), strInput.size(), hash);
    return string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

string strComputeMAC(const string& strMessage, const string& strKi, const string& strContext) 
{
    string strMacKey = strF_Prime(strKi, strContext);

    unsigned char result[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;

    HMAC(EVP_sha256(),
        reinterpret_cast<const unsigned char*>(strMacKey.data()), strMacKey.size(),
        reinterpret_cast<const unsigned char*>(strMessage.data()), strMessage.size(),
        result, &len);

    return strToHexString(result, len);
}

bool bIsValidKey(const string& strPKey, const string& strKeyZero, int nTotalkeys) 
{
    bool bResult = false;
    string strSomeKey;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char*)strPKey.c_str(), strPKey.size(), hash);
    strSomeKey = strToHexString(hash, SHA256_DIGEST_LENGTH);

    for (int i = 0; i < nTotalkeys; ++i) 
    {
        if (strSomeKey == strKeyZero) 
        {
            bResult = true;
            break;
        }
        else 
        {
            SHA256((unsigned char*)strSomeKey.c_str(), strSomeKey.size(), hash);
            strSomeKey = strToHexString(hash, SHA256_DIGEST_LENGTH);
        }
    }

    return bResult;
}

string strDerivePastKeyForInterval(const string& strDisclosedKey, int nLostKeyIndex, int nDisclosedKeyIndex)
{
    int nComputeTimes = nDisclosedKeyIndex - nLostKeyIndex;
    string strSomeKey = strDisclosedKey;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    for (int i = 0; i < nComputeTimes; i++)
    {
        SHA256((unsigned char*)strSomeKey.c_str(), strSomeKey.size(), hash);
        strSomeKey = strToHexString(hash, SHA256_DIGEST_LENGTH);
    }

    return strSomeKey;
}

bool bReceiveInitPacket(TeslaInitPacket& packet, int port) 
{
    socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        cout << "Receive Protocol Packet Socket Create Failed!" << endl;
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sockfd, (sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR) 
    {
        cout << "Bind Failed!" << endl;
        return false;
    }
    char buffer[2048];
    sockaddr_in senderAddr;
    socklen_t len = sizeof(senderAddr);

    ssize_t recvLen = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
        (sockaddr*)&senderAddr, &len);
    buffer[recvLen] = '\0';

    json received = json::parse(buffer);
    packet = TeslaInitPacket::from_json(received);

    CLOSESOCKET(sockfd);

    return true;
}

bool bReceiveProtocolPacket(TeslaProtocolPacket& packet, int port)
{
    socket_t sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        cout << "Receive Protocol Packet Socket Create Failed!" << endl;
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sockfd, (sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR) 
    {
        cout << "Bind Failed!" << endl;
        CLOSESOCKET(sockfd);
        return false;
    }
    char buffer[2048];
    sockaddr_in senderAddr;
    socklen_t len = sizeof(senderAddr);

    ssize_t recvLen = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
        (sockaddr*)&senderAddr, &len);
    if (recvLen <= 0)
    {
        return false;
    }

    buffer[recvLen] = '\0';

    json received = json::parse(buffer);
    packet = TeslaProtocolPacket::from_json(received);

    CLOSESOCKET(sockfd);

    return true;
}

static string strToHex(const string& strInput) {
    static const char* hex_digits = "0123456789abcdef";
    string strOutput;
    strOutput.reserve(strInput.size() * 2);
    for (unsigned char c : strInput) {
        strOutput.push_back(hex_digits[(c >> 4) & 0x0F]);
        strOutput.push_back(hex_digits[c & 0x0F]);
    }
    return strOutput;
}

static string strHashFunc(const string& strData) {
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
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

// 每个 slot 的条目（当三者都非空时，才可参与聚合）
struct SlotItem {
    string strMsg;   // m_i
    string strKey;   // 披露的 K_i
    string strContext;
};

// 每组（10 条）的“桶”：用 map<int, SlotItem> 可保持 slot 有序，便于顺序聚合
struct GroupBucket {
    map<int, SlotItem> items;                 // slot -> SlotItem
    chrono::steady_clock::time_point touch;   // 最近一次加入时间
};

// 全局/外部：每个 group_id 的桶
unordered_map<string, unordered_map<int, GroupBucket>> g_groups_by_sender;

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

/****************************************************
*按行线性扫描 matrix，恢复“正确子集 / 坏子集”
*
*输入：
* vecTags     – 本地重算的 t_j 列表（顺序就是 slot 顺序）
* vecTauRecv  – 收到的 SAMD 聚合标签 τ_i（长度 ≤ u）
* 输出：
* vecGoodPos  – 在 vecTags 中的“好”位置集合（下标）
* vecBadPos   – “坏”位置集合（下标，对应篡改或丢包）
* 返回：
* true  – 所有位置均被判定为好（vecBadPos 为空）
* false – 存在坏位置
*  ****************************************************/
static int Samd_DSAVrfy(
    const vector<string>& vecTags,
    const vector<string>& vecTauRecv,
    vector<int>& vecGoodPos,
    vector<int>& vecBadPos
)
{
    EnsureSamdGtMatrix();

    int m = (int)vecTags.size();
    int u = g_SamdKSGt.u;
    int uRecv = (int)vecTauRecv.size();

    vecGoodPos.clear();
    vecBadPos.clear();

    if (m == 0) {
        return true;
    }

    // 初始假设每个位置都是“可能坏的”
    vector<int> isGood(m, 0);

    // 对每一行做一次线性扫描
    for (int i = 0; i < u && i < uRecv; ++i) {
        if (vecTauRecv[i].empty()) {
            continue;   // 这一行对本组不起作用
        }

        vector<int> idxList;
        vector<string> subset;

        for (int j = 0; j < m && j < g_SamdKSGt.N; ++j) {
            if (g_SamdKSGt.G[i][j] == 1) {
                idxList.push_back(j);
                subset.push_back(vecTags[j]);
            }
        }
        if (subset.empty()) {
            continue;
        }

        string tauCalc = strSamdHashFromMacList(subset);

        if (tauCalc == vecTauRecv[i]) {
            // 该测试行通过 ⇒ 行上覆盖的所有 slot 均为“好”
            int len = (int)idxList.size();
            for (int k = 0; k < len; ++k) {
                int pos = idxList[k];
                if (pos >= 0 && pos < m) {
                    isGood[pos] = 1;
                }
            }
        }
    }

    // 收集好 / 坏位置
    for (int j = 0; j < m; ++j) {
        if (isGood[j]) {
            vecGoodPos.push_back(j);
        }
        else {
            vecBadPos.push_back(j);
        }
    }

    return vecBadPos.size();
}

/****************************************************
 * 和你现有 GroupBucket 的封装版本：
 *   bVerifyGroupSAMD
 *
 * 功能：
 *   - 从 gb 中抽取有 message + key 的 slot；
 *   - 用 TESLA 的规则重算每条 MAC（t_j）；
 *   - 调用 Samd_DSAVrfy 做线性扫描，输出“好 / 坏 slot”；
 *
 * 输入：
 *   nGroupId    – 组号（仅用于日志）
 *   gb          – 本组的缓存（map<int, SlotItem>）
 *   vecTauRecv  – 本组收到的 SAMD 聚合标签向量 τ_i
 * 输出：
 *   vecGoodSlots – 被判为“好”的全局 slot 编号集合
 *   vecBadSlots  – 被判为“坏/丢包”的全局 slot 编号集合
 * 返回：
 *   true  – 所有 slot 均为好（vecBadSlots 为空）
 *   false – 存在坏 slot
 ****************************************************/
static bool bVerifyGroupSAMD(
    int nGroupId,
    GroupBucket& gb,
    const vector<string>& vecTauRecv,
    vector<int>& vecGoodSlots,
    vector<int>& vecBadSlots
)
{
    // 1) 从 group 中抽出有完整信息的 slot，并重算 MAC
    vector<int> vecSlotIds;      // 映射：位置 j -> 全局 slot 编号
    vector<string> vecTags;      // t_j = MAC(m_j, k_j)

    for (map<int, SlotItem>::iterator it = gb.items.begin(); it != gb.items.end(); ++it) {
        int nSlot = it->first;
        const SlotItem& item = it->second;

        // SAMD 构造里，只需要消息 + 密钥就能重算 t_j
        if (item.strMsg.empty() || item.strKey.empty()) {
            continue;
        }

        // 注意这里要跟发送端保持同一条 MAC 计算规则
        // 你之前在 strTauCalc 里用的是 strContext + to_string(slot)
        string strMacCalc = strComputeMAC(
            item.strMsg,
            item.strKey,
            item.strContext + to_string(nSlot)
        );

        vecSlotIds.push_back(nSlot);
        vecTags.push_back(strMacCalc);
    }

    // 2) 调用 SAMD 的 DSAVrfy，在线性时间内恢复“好 / 坏子集”
    vector<int> goodPos;
    vector<int> badPos;
    int nBadSlotCnt = Samd_DSAVrfy(vecTags, vecTauRecv, goodPos, badPos);
    if (nBadSlotCnt > N_DECTECING)
    {
        cout << "The current network environment is poor，lost packet is over DECTECING" << endl;
        return false;
    }

    vecGoodSlots.clear();
    vecBadSlots.clear();

    int goodCount = (int)goodPos.size();
    for (int i = 0; i < goodCount; ++i) {
        int pos = goodPos[i];
        if (pos >= 0 && pos < (int)vecSlotIds.size()) {
            vecGoodSlots.push_back(vecSlotIds[pos]);
        }
    }

    int badCount = (int)badPos.size();
    for (int i = 0; i < badCount; ++i) {
        int pos = badPos[i];
        if (pos >= 0 && pos < (int)vecSlotIds.size()) {
            vecBadSlots.push_back(vecSlotIds[pos]);
        }
    }

    // 简单日志
    if (nBadSlotCnt > 0) {
        cerr << "[SAMD] group " << nGroupId << " bad slots: ";
        for (int i = 0; i < (int)vecBadSlots.size(); ++i) {
            cerr << vecBadSlots[i] << " ";
        }
        cerr << endl;
        return false;
    }

    return true;
}



// 触发聚合并清空该组（满组、超时、结束时都会调用）
static void FlushGroup(string strSenderId, int nGroupId, const vector<string>& vecRecvTau)
{
    auto itSender = g_groups_by_sender.find(strSenderId);
    if (itSender == g_groups_by_sender.end()) return;

    auto& groups = itSender->second;
    auto itGroup = groups.find(nGroupId);
    if (itGroup == groups.end()) return;

    GroupBucket& gb = itGroup->second;
    if (gb.items.empty()) return;

    vector<int> vecGoodSlots;
    vector<int> vecBadSlots;
    //const bool bOk = bVerifyGroupSa2(group_id, gb);
    const bool bOk = bVerifyGroupSAMD(nGroupId, gb, vecRecvTau, vecGoodSlots, vecBadSlots);
    if (bOk)
    {
        cout << "Sender: " << strSenderId
            << " [flush] group " << nGroupId
            << " count=" << gb.items.size()
            << " result=" << bOk << endl;
    }

    gb.items.clear(); // 清空该组
}

// 工具函数：把某个 slot 的条目放入对应组
void UpsertSlotIntoGroup(
    string strID,
    int nGroupId,
    int nSlot,
    const string& strMsg,
    const string& strKey,
    const vector<string>& vecRecvTau,
    const string& strContext
) 
{
    GroupBucket& gb = g_groups_by_sender[strID][nGroupId];
    gb.touch = chrono::steady_clock::now();

    // 获取或创建该 slot 的 item
    SlotItem& item = gb.items[nSlot];
    if (!strMsg.empty()) item.strMsg = strMsg;
    if (!strKey.empty()) item.strKey = strKey;
    if (!strContext.empty()) item.strContext = strContext;

    // 判断当前组内完整项数量
    int nComplete = 0;
    for (map<int, SlotItem>::iterator it = gb.items.begin(); it != gb.items.end(); ++it) 
    {
        const SlotItem& itVal = it->second;
        if (!itVal.strMsg.empty() && !itVal.strKey.empty())
            ++nComplete;
    }

    if (nComplete >= N_GROUP_SIZE && !vecRecvTau.empty())
    {
        FlushGroup(strID, nGroupId, vecRecvTau);
        return;
    }
    /*else
    {
        cout << "Group: " << nGroupId << "Lost Tau, Ignore." << endl;
        return;
    }*/
}

// 工具函数：检查所有组的超时（每次 while 循环底部调用）
//void CheckAllGroupsTimeout() 
//{
//    chrono::steady_clock::time_point now = chrono::steady_clock::now();
//    for (unordered_map<int, GroupBucket>::iterator it = g_groups.begin(); it != g_groups.end(); ++it) 
//    {
//        int gid = it->first;
//        GroupBucket& gb = it->second;
//        if (!gb.items.empty() && (now - gb.touch) > chrono::milliseconds(100)) 
//        {
//            FlushGroup("", gid);
//            gb.touch = now;
//        }
//    }
//}



//Init 包处理，改为 per-sender 上下文 
static void HandleInitForSender(const string& strSenderId, const TeslaInitPacket& initPkt) {
    auto pCtx = GetOrCreateCtx(strSenderId);

    pCtx->strKey0 = initPkt.strCommitmentKey;//密钥单向链key0，在初始阶段发送给接收方
    pCtx->nTotalKeys = initPkt.nTotalKeys;//密钥总数
    pCtx->nDelay = initPkt.nDisclosureDelay;//密钥披露延迟
    pCtx->nIntervalLengthMs = initPkt.nIntervalLengthMs;
    pCtx->strContext = initPkt.strContext;//F‘生成messageMac的上下文

    pCtx->lDeltaMs = lEstimateTimeOffset(initPkt);//估算发送方时间上界的Δ

    // 重新分配缓冲，长度 = N + 1（与你原逻辑一致）
    pCtx->vecReceiveMessageBuffer.assign(pCtx->nTotalKeys + 1, "");
    pCtx->vecReceiveMessageKeyBuffer.assign(pCtx->nTotalKeys + 1, "");

    // 重置计数
    pCtx->nValidKeyCnt = 0; //合法的密钥总数
    pCtx->nDelayMemoryKeyCnt = 0; //延迟记录密钥的次数
    pCtx->bIsLostPacket = false; //判断接收过程中是否丢弃不在合法时间内的报文
    pCtx->nLastKeyIndex = 0; //满组进行聚合验证的最后一个密钥号
    pCtx->nGroupCnt = 0; //分组的个数
    pCtx->nRecvTauIndex = 0;
    pCtx->nLastTauIndex = 0;
}

//每个数据包的处理逻辑
static void HandlePacketForSender(const string& strSenderId, const TeslaProtocolPacket& protocolPacket)
{
    auto pCtx = GetOrCreateCtx(strSenderId);
    //pCtx->tpLastTouch = std::chrono::steady_clock::now();

    int nKeyIndex = -1;

    ////估算发送方的时间上界，确认收到的数据包是不是合法时间段内收到的
    //long long now = lCurrentTimeMillis();
    //int sender_interval = nComputeSenderUpperBoundInterval(now % (pCtx->nTotalKeys * pCtx->nIntervalLengthMs), pCtx->nIntervalLengthMs, pCtx->lDeltaMs);
    //if (sender_interval > protocolPacket.nIndex + pCtx->nDelay)
    //{
    //    cout << "[Not Safe] No." << protocolPacket.nIndex << " Packet May Have Been Exposed, Abandon!" << endl;

    //    return;
    //}
    //else
    //{
    //    cout << "[SAFE] No." << protocolPacket.nIndex << " Packet Is Valid, Continue!" << endl;
    //}



    //密钥披露之前
    if (protocolPacket.strDisclosedKey == "zero")
    {
        cout << "No." << protocolPacket.nIndex
            << " Packet Received, Key Not Yet Disclosed" << endl;
        pCtx->vecReceiveMessageBuffer[protocolPacket.nIndex] = protocolPacket.strMessage;
    }
    else
    {
        if (!bIsValidKey(protocolPacket.strDisclosedKey, pCtx->strKey0, pCtx->nTotalKeys)) {
            cout << "Received No. " << (protocolPacket.nIndex - pCtx->nDelay)
                << " Key Error, Not TESLA" << endl;
            return;
        }

        nKeyIndex = protocolPacket.nIndex - pCtx->nDelay + 1;
        if (nKeyIndex < 0 || nKeyIndex >= pCtx->nTotalKeys) {
            cerr << "Key index out of range: " << nKeyIndex << endl;
            return;
        }

        if (protocolPacket.vecSamdTau.empty())
        {
            pCtx->vecReceiveMessageKeyBuffer[nKeyIndex] = protocolPacket.strDisclosedKey;
            pCtx->vecReceiveMessageBuffer[protocolPacket.nIndex] = protocolPacket.strMessage;
            ++pCtx->nValidKeyCnt;
            cout << "Key slot " << nKeyIndex << " received ("
                << pCtx->nValidKeyCnt << "/" << pCtx->nTotalKeys - 1 << ")" << endl;
        }
        else
        {
            pCtx->vecSamdTau = protocolPacket.vecSamdTau;
            pCtx->vecReceiveMessageKeyBuffer[nKeyIndex] = protocolPacket.strDisclosedKey;
            pCtx->vecReceiveMessageBuffer[protocolPacket.nIndex] = protocolPacket.strMessage;
            pCtx->nRecvTauIndex = protocolPacket.nIndex;
            ++pCtx->nValidKeyCnt;
            cout << "Key slot " << nKeyIndex << " received ("
                << pCtx->nValidKeyCnt << "/" << pCtx->nTotalKeys - 1 << ")" << endl;
        }
    }

    if (pCtx->nRecvTauIndex == nKeyIndex)
    {
        pCtx->nGroupCnt++;
        for (int i = pCtx->nLastTauIndex + 1; i <= pCtx->nRecvTauIndex; i++)
        {
            UpsertSlotIntoGroup(
                strSenderId,
                pCtx->nGroupCnt,
                i,
                pCtx->vecReceiveMessageBuffer[i],
                pCtx->vecReceiveMessageKeyBuffer[i],
                pCtx->vecSamdTau,
                pCtx->strContext
            );
        }

        pCtx->nLastTauIndex = pCtx->nRecvTauIndex;
    }
}

//Init 监听线程（9999）循环调用bReceiveInitPacket以确保能够接收到每个新的发送端的init
static void ThreadListenLoop_Init() 
{
    while (g_bRunning.load()) {
        TeslaInitPacket initPkt;
        if (!bReceiveInitPacket(initPkt, 9999))
        {
            // 可小睡一下避免空转
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        string strSenderId = initPkt.strSenderId;
        // 1) 注册 strand & 标记为已知 sender
        EnsureStrandExists(strSenderId);
        MarkSenderKnown(strSenderId);

        // 2) 把“初始化处理”投递到该 sender 的 strand
        PostToSender(strSenderId, [strSenderId, initPkt] {
            HandleInitForSender(strSenderId, initPkt);
            });
    }
}

//数据包监听线程，循环调用 bReceiveProtocolPacket
static void ThreadListenLoop_UDP() 
{
    while (g_bRunning.load()) 
    {
        TeslaProtocolPacket stPkt;
        if (!bReceiveProtocolPacket(stPkt, 7777)) 
        {
            // 可小睡一下避免空转
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        //未注册 sender 直接丢弃
        string strSenderId = stPkt.strSenderId;
        if (!IsSenderKnown(strSenderId)) {
            std::cerr << "[DataListen] drop unknown sender: " << strSenderId << "\n";
            continue;
        }
        //确保 strand 存在（理论上 Init 时已创建，这里只是兜底）
        EnsureStrandExists(strSenderId);

        //把该包投递到“per-sender 串行通道”，调用已有的 HandlePacketForSender
        PostToSender(strSenderId, [strSenderId, stPkt] {HandlePacketForSender(strSenderId, stPkt);});
    }
}


int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
    {
        std::cerr << "WSAStartup failed!\n";
        return -1;
    }
#endif
    //接收TESLA协议数据包，待完成
    /*receiver验证功能
     *1、计算时间上界，打开数据包检查index，判断是否是合法的数据包 √
     *2、若当前数据包index已达到密钥披露的数据包，则拿出密钥按照初始阶段sender发送的F和K0验证密钥是否合法 √
     *3、利用F‘将披露的密钥计算MAC密钥，将属于该密钥的message计算HMAC判断与传来的MAC是否相同 √
     */

    g_pThreadPool.reset(new CThreadPool(g_nWorkerThreads));

    // 2) 启动监听线程（UDP 7777）
    g_bRunning.store(true);
    thread thInit(ThreadListenLoop_Init);
    thread thData(ThreadListenLoop_UDP);

    // 3) 启动后台回收线程（可选）
    thread thGc([&]
    {
        while (g_bRunning.load()) 
        {
            this_thread::sleep_for(chrono::seconds(5));
            GcIdleStrands();
        }
    });

    // 4) 等待“结束条件”
    while (true) 
    {
        this_thread::sleep_for(chrono::seconds(1));
        // 如果你有“收到 index == nTotalKeys + 1”的结束标志，可以在 HandlePacketForSender 里设置一个原子标志位
        // 然后在这里检测那个标志位，跳出循环。
        // if (g_bFinished.load()) break;
    }

    // 5) 停机：收尾
    g_bRunning.store(false);
    if (thInit.joinable())
    {
        thInit.join();
    }
    if (thData.joinable())
    {
        thData.join();
    }
    if (thGc.joinable())
    {
        thGc.join();
    }
    g_pThreadPool.reset();


#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}