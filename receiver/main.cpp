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
const int N_GROUP_SIZE = 10;

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
    vector<string> vecReceiveMessageMacBuffer;     // receiveMessageMACBuffer
    vector<string> vecReceiveMessageKeyBuffer;     // receiveMessageKEYBuffer

    int nValidKeyCnt = 0;
    int nDelayMemoryKeyCnt = 0;
    bool bIsLostPacket = false;
    int nLastKeyIndex = 0;
    int nGroupCnt = 0;

    // 分组聚合需要的时间戳等（可选）
    //std::chrono::steady_clock::time_point tpLastTouch = std::chrono::steady_clock::now();
};

struct TeslaProtocolPacket {
    string strSenderId;
    int nIndex;
    string strMessage;
    string strMac;
    string strDisclosedKey;

    static TeslaProtocolPacket from_json(const json& j) {
        return { j["strSenderId"], j["nIndex"], j["strMessage"], j["strMac"], j["strDisclosedKey"] };
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
        << ppacket.strMessage << " | MAC = " << ppacket.strMac << " | Key = "
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

struct TagEntry {
    int nSlot;
    string strMac;
};

static void AppendU32Le(string& strOut, uint32_t value) {
    strOut.push_back(static_cast<char>(value & 0xFF));
    strOut.push_back(static_cast<char>((value >> 8) & 0xFF));
    strOut.push_back(static_cast<char>((value >> 16) & 0xFF));
    strOut.push_back(static_cast<char>((value >> 24) & 0xFF));
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

string strSeqAgg(const vector<TagEntry>& vecTags) {
    string strBuffer;
    strBuffer.reserve(vecTags.size() * 48);
    for (const auto& e : vecTags) {
        strBuffer.push_back(0x01);                      // 分隔符
        AppendU32Le(strBuffer, static_cast<uint32_t>(e.nSlot));               // slot 编码
        AppendU32Le(strBuffer, e.strMac.size());         // MAC 长度前缀
        strBuffer.append(e.strMac);                        // MAC 内容
    }
    return strToHex(strHashFunc(strBuffer));
}

// 每个 slot 的条目（当三者都非空时，才可参与聚合）
struct SlotItem {
    string strMsg;   // m_i
    string strMac;   // 报文携带的 t_i
    string strKey;   // 披露的 K_i
    string strContext;
};

// 每组（10 条）的“桶”：用 map<int, SlotItem> 可保持 slot 有序，便于顺序聚合
struct GroupBucket {
    map<int, SlotItem> items;                 // slot -> SlotItem
    chrono::steady_clock::time_point touch;   // 最近一次加入时间
};

// 全局/外部：每个 group_id 的桶
unordered_map<int, GroupBucket> g_groups;

// 组内聚合验证 + 回退定位（成功返回 true；失败打印错误 slot）
static bool bVerifyGroupSa2(int nGroupId, GroupBucket& gb) {
    if (gb.items.empty()) return true; // 空组当通过

    // 构造“接收 MAC 序列”
    vector<TagEntry> vecRecvTags;
    vecRecvTags.reserve(gb.items.size());
    for (map<int, SlotItem>::iterator kv = gb.items.begin(); kv != gb.items.end(); ++kv) 
    {
        const int nSlot = kv->first;
        const SlotItem& it = kv->second;
        // 只有三件套都齐了的才参与（m、mac、key）
        if (!it.strMsg.empty() && !it.strMac.empty() && !it.strKey.empty()) 
        {
            TagEntry entry;
            entry.nSlot = nSlot;
            entry.strMac = it.strMac;
            vecRecvTags.push_back(entry);
        }
    }
    if (vecRecvTags.empty()) return true; // 尚未齐的，先不报错

    // τ_recv：直接对“收到的 MAC 序列”做聚合
    const string strTauRecv = strSeqAgg(vecRecvTags);

    // τ_calc：对“披露密钥重算的 MAC 序列”做聚合
    vector<TagEntry> vecCalcTags;
    vecCalcTags.reserve(vecRecvTags.size());
    for (map<int, SlotItem>::iterator kv = gb.items.begin(); kv != gb.items.end(); ++kv) 
    {
        const int slot = kv->first;
        const SlotItem& it = kv->second;
        if (!it.strMsg.empty() && !it.strMac.empty() && !it.strKey.empty()) 
        {
            string strMacCalc = strComputeMAC(it.strMsg, it.strKey, it.strContext + to_string(slot));
            TagEntry entry;
            entry.nSlot = slot;
            entry.strMac = strMacCalc;
            vecCalcTags.push_back(entry);
        }
    }
    const string strTauCalc = strSeqAgg(vecCalcTags);

    // 比较 τ（常量时间比较）
    const bool ok = (strTauRecv == strTauCalc);

    if (!ok) 
    {
        cerr << "[SAVrfy FAIL] group " << nGroupId
            << " size=" << gb.items.size()
            << " -> fallback locate" << endl;

        // 逐条定位：找出哪几个 slot 的 MAC 不一致
        for (map<int, SlotItem>::iterator kv = gb.items.begin(); kv != gb.items.end(); ++kv) 
        {
            const int nSlot = kv->first;
            const SlotItem& it = kv->second;
            if (it.strMsg.empty() || it.strMac.empty() || it.strKey.empty())
            {
                continue;
            }
            string strMacCalc = strComputeMAC(it.strMsg, it.strKey, it.strContext + to_string(nSlot + 1));
            if (it.strMac != strMacCalc)
            {
                cerr << "  - BAD slot " << nSlot << endl;
            }
        }
    }

    return ok;
}

// 触发聚合并清空该组（满组、超时、结束时都会调用）
static void FlushGroup(string strSenderId, int group_id) 
{
    unordered_map<int, GroupBucket>::iterator it = g_groups.find(group_id);
    if (it == g_groups.end()) return;

    GroupBucket& gb = it->second;
    if (gb.items.empty()) return;

    const bool bOk = bVerifyGroupSa2(group_id, gb);
    cout << "Sender: " << strSenderId
        << " [flush] group " << group_id
        << " count=" << gb.items.size()
        << " result=" << bOk << endl;

    gb.items.clear(); // 清空该组
}

// 工具函数：把某个 slot 的条目放入对应组
void UpsertSlotIntoGroup(
    string strID,
    int nGroupId,
    int nSlot,
    const string& strMsg,
    const string& strMac,
    const string& strKey,
    const string& strContext
) 
{
    GroupBucket& gb = g_groups[nGroupId];
    gb.touch = chrono::steady_clock::now();

    // 获取或创建该 slot 的 item
    SlotItem& item = gb.items[nSlot];
    if (!strMsg.empty()) item.strMsg = strMsg;
    if (!strMac.empty()) item.strMac = strMac;
    if (!strKey.empty()) item.strKey = strKey;
    if (!strContext.empty()) item.strContext = strContext;

    // 判断当前组内完整项数量
    int nComplete = 0;
    for (map<int, SlotItem>::iterator it = gb.items.begin(); it != gb.items.end(); ++it) 
    {
        const SlotItem& itVal = it->second;
        if (!itVal.strMsg.empty() && !itVal.strMac.empty() && !itVal.strKey.empty())
            ++nComplete;
    }

    if (nComplete >= N_GROUP_SIZE)
    {
        FlushGroup(strID, nGroupId);
    }
}

// 工具函数：检查所有组的超时（每次 while 循环底部调用）
void CheckAllGroupsTimeout() 
{
    chrono::steady_clock::time_point now = chrono::steady_clock::now();
    for (unordered_map<int, GroupBucket>::iterator it = g_groups.begin(); it != g_groups.end(); ++it) 
    {
        int gid = it->first;
        GroupBucket& gb = it->second;
        if (!gb.items.empty() && (now - gb.touch) > chrono::milliseconds(100)) 
        {
            FlushGroup("", gid);
            gb.touch = now;
        }
    }
}

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
    pCtx->vecReceiveMessageMacBuffer.assign(pCtx->nTotalKeys + 1, "");
    pCtx->vecReceiveMessageKeyBuffer.assign(pCtx->nTotalKeys + 1, "");

    // 重置计数
    pCtx->nValidKeyCnt = 0; //合法的密钥总数
    pCtx->nDelayMemoryKeyCnt = 0; //延迟记录密钥的次数
    pCtx->bIsLostPacket = false; //判断接收过程中是否丢弃不在合法时间内的报文
    pCtx->nLastKeyIndex = 0; //满组进行聚合验证的最后一个密钥号
    pCtx->nGroupCnt = 0; //分组的个数
}

//每个数据包的处理逻辑
static void HandlePacketForSender(const string& strSenderId, const TeslaProtocolPacket& protocolPacket) 
{
    auto pCtx = GetOrCreateCtx(strSenderId);
    //pCtx->tpLastTouch = std::chrono::steady_clock::now();

    int keyIndex = 0;

    //估算发送方的时间上界，确认收到的数据包是不是合法时间段内收到的
    long long now = lCurrentTimeMillis();
    int sender_interval = nComputeSenderUpperBoundInterval(now % (pCtx->nTotalKeys * pCtx->nIntervalLengthMs), pCtx->nIntervalLengthMs, pCtx->lDeltaMs);
    if (sender_interval > protocolPacket.nIndex + pCtx->nDelay)
    {
        cout << "[Not Safe] No." << protocolPacket.nIndex << " Packet May Have Been Exposed, Abandon!" << endl;
        
        return ;
    }
    else
    {
        cout << "[SAFE] No." << protocolPacket.nIndex << " Packet Is Valid, Continue!" << endl;
    }


    
    //密钥披露之前
    if (protocolPacket.strDisclosedKey == "zero")
    {
        cout << "No." << protocolPacket.nIndex
            << " Packet Received, Key Not Yet Disclosed" << endl;
        pCtx->vecReceiveMessageBuffer[protocolPacket.nIndex] = protocolPacket.strMessage;
        pCtx->vecReceiveMessageMacBuffer[protocolPacket.nIndex] = protocolPacket.strMac;
    }
    else
    {
        if (!bIsValidKey(protocolPacket.strDisclosedKey, pCtx->strKey0, pCtx->nTotalKeys)) {
            cout << "Received No. " << (protocolPacket.nIndex - pCtx->nDelay)
                << " Key Error, Not TESLA" << endl;
            return;
        }

        keyIndex = protocolPacket.nIndex - pCtx->nDelay + 1;
        if (keyIndex < 0 || keyIndex >= pCtx->nTotalKeys) {
            cerr << "Key index out of range: " << keyIndex << endl;
            return;
        }

        
        if (!pCtx->vecReceiveMessageBuffer[keyIndex].empty() && !pCtx->vecReceiveMessageMacBuffer[keyIndex].empty())
        {
            pCtx->vecReceiveMessageKeyBuffer[keyIndex] = protocolPacket.strDisclosedKey;
            ++pCtx->nValidKeyCnt;
            cout << "Key slot " << keyIndex << " received ("
                << pCtx->nValidKeyCnt << "/" << pCtx->nTotalKeys - 1 << ")" << endl;
        }
        else
        {
            for (int i = 1; i < keyIndex; i++)
            {
                if (pCtx->vecReceiveMessageKeyBuffer[i].empty() &&
                    !pCtx->vecReceiveMessageBuffer[i].empty() &&
                    !pCtx->vecReceiveMessageMacBuffer[i].empty())
                {
                    pCtx->vecReceiveMessageKeyBuffer[i] = strDerivePastKeyForInterval(protocolPacket.strDisclosedKey, i, keyIndex);
                    ++pCtx->nValidKeyCnt;
                }
            }
        }
        

        if (!protocolPacket.strMessage.empty() && !protocolPacket.strMac.empty()) {
            pCtx->vecReceiveMessageBuffer[protocolPacket.nIndex] = protocolPacket.strMessage;
            pCtx->vecReceiveMessageMacBuffer[protocolPacket.nIndex] = protocolPacket.strMac;
        }

    }

    if (pCtx->nValidKeyCnt % N_GROUP_SIZE == 0 && pCtx->nValidKeyCnt > 0)
    {
        int nUpsertCnt = 0;
        int nCurrentIndex = keyIndex;
        pCtx->nGroupCnt++;
        while (nUpsertCnt < N_GROUP_SIZE)
        {
            if (!pCtx->vecReceiveMessageBuffer[nCurrentIndex].empty() &&
                !pCtx->vecReceiveMessageMacBuffer[nCurrentIndex].empty() &&
                !pCtx->vecReceiveMessageKeyBuffer[nCurrentIndex].empty())
            {
                UpsertSlotIntoGroup(
                    strSenderId,
                    pCtx->nGroupCnt,
                    nCurrentIndex,
                    pCtx->vecReceiveMessageBuffer[nCurrentIndex],
                    pCtx->vecReceiveMessageMacBuffer[nCurrentIndex],
                    pCtx->vecReceiveMessageKeyBuffer[nCurrentIndex],
                    pCtx->strContext
                );
                nUpsertCnt++;
            }
            nCurrentIndex--;
        }
    }

    // 每轮检查一次组超时（用于丢包处理）
    //CheckAllGroupsTimeout();
    /*chrono::steady_clock::time_point now = chrono::steady_clock::now();
    GroupBucket& gb = g_groups[pCtx->nGroupCnt];*/

    if (protocolPacket.nIndex == pCtx->nTotalKeys + 1)
    {
        pCtx->nGroupCnt++;
        int nUpsertCnt = pCtx->nValidKeyCnt % N_GROUP_SIZE;
        int nCurrentIndex = keyIndex;
        while (nUpsertCnt > 0)
        {
            if (!pCtx->vecReceiveMessageBuffer[nCurrentIndex].empty() &&
                !pCtx->vecReceiveMessageMacBuffer[nCurrentIndex].empty() &&
                !pCtx->vecReceiveMessageKeyBuffer[nCurrentIndex].empty())
            {
                UpsertSlotIntoGroup(
                    strSenderId,
                    pCtx->nGroupCnt,
                    nCurrentIndex,
                    pCtx->vecReceiveMessageBuffer[nCurrentIndex],
                    pCtx->vecReceiveMessageMacBuffer[nCurrentIndex],
                    pCtx->vecReceiveMessageKeyBuffer[nCurrentIndex],
                    pCtx->strContext
                );
                nUpsertCnt--;
            }
            nCurrentIndex--;
        }

        // 手动触发该组的最终 flush（即使未满）
        int group_id = pCtx->nGroupCnt;
        FlushGroup(strSenderId, group_id);
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