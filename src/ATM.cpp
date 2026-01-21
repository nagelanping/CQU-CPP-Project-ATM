// 依赖项： OpenSSL, windows.h, tlhelp32.h
// 推荐使用 MSYS2 (mingw-w64) 编译环境
// 编译示例（带优化）：
// g++ -std=c++11 -O2 -Wall -o ATM.exe ATM.cpp -lssl -lcrypto -lws2_32 -lgdi32

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>
#include <tlhelp32.h>

using namespace std;

// 调试开关
// #define DEBUG_LOADING 0

// 调试日志函数（已注释）
/*
static void logDebug(const string &msg)
{
    static ofstream logFile("atm_debug.log", ios::app);
    if (logFile.is_open())
    {
        time_t now = time(nullptr);
        char timeStr[64];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));
        logFile << "[" << timeStr << "] " << msg << endl;
        logFile.flush();
    }
}

#ifdef DEBUG_LOADING
#define DEBUG_LOG(msg)                        \
    do                                        \
    {                                         \
        cout << "[DEBUG] " << (msg) << endl;  \
        logDebug(string("[DEBUG] ") + (msg)); \
    } while (0)
#else
#define DEBUG_LOG(msg) \
    do                 \
    {                  \
    } while (0)
#endif
*/

// 正式版本：禁用调试日志
#define DEBUG_LOG(msg) do {} while(0)

// ==================== 反逆向工程保护 ====================

// 简单的编译时字符串XOR加密
#define XOR_KEY 0x5A

class ObfuscatedString
{
private:
    char *data;
    size_t len;

    void decrypt()
    {
        if (data)
        {
            for (size_t i = 0; i < len; i++)
            {
                data[i] ^= XOR_KEY;
            }
        }
    }

public:
    ObfuscatedString(const char *str)
    {
        len = strlen(str);
        data = new char[len + 1];
        for (size_t i = 0; i < len; i++)
        {
            data[i] = str[i] ^ XOR_KEY;
        }
        data[len] = '\0';
    }

    ~ObfuscatedString()
    {
        if (data)
        {
            memset(data, 0, len);
            delete[] data;
        }
    }

    const char *get()
    {
        decrypt();
        return data;
    }
};

// 反调试检测
namespace AntiDebug
{
    // 检测调试器
    bool isDebuggerPresent()
    {
        return IsDebuggerPresent() != 0;
    }

    // 检测远程调试
    bool checkRemoteDebugger()
    {
        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        return isRemoteDebuggerPresent != 0;
    }

    // 检测调试器进程
    bool detectDebuggerProcess()
    {
        const wchar_t *debuggerNames[] = {
            L"ollydbg.exe", L"x64dbg.exe", L"windbg.exe",
            L"idaq.exe", L"idaq64.exe", L"ida.exe", L"ida64.exe"};

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe32))
        {
            do
            {
                for (const wchar_t *name : debuggerNames)
                {
                    if (_wcsicmp(pe32.szExeFile, name) == 0)
                    {
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32NextW(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return false;
    }

    // 时间检测（检测单步调试）
    bool detectTiming()
    {
        DWORD start = GetTickCount();
        // 虚假操作
        int dummy = 0;
        for (int i = 0; i < 10; i++)
        {
            dummy += i;
        }
        DWORD end = GetTickCount();
        return (end - start) > 100; // 如果执行时间过长，可能在调试
    }

    // 综合检测
    bool detect()
    {
        static int checkCount = 0;
        checkCount++;

        // 使用虚假分支混淆
        bool result = false;
        int fakeVar = checkCount * 7 + 3;
        if (fakeVar % 2 == 0)
        {
            result = isDebuggerPresent();
        }
        else
        {
            result = isDebuggerPresent();
        }

        if (checkRemoteDebugger())
            result = true;

        if (checkCount % 5 == 0 && detectDebuggerProcess())
            result = true;

        if (checkCount % 10 == 0 && detectTiming())
            result = true;

        return result;
    }

    // 反调试响应
    void respond()
    {
        // 清除敏感内存
        MessageBoxA(NULL, "Security violation detected!", "Error", MB_OK | MB_ICONERROR);
        exit(-1);
    }
}

// 虚假代码混淆
inline void __declspec(noinline) fakeFunction1()
{
    volatile int x = rand() % 100;
    x = x * x + x - 42;
}

inline void __declspec(noinline) fakeFunction2()
{
    volatile char buffer[64];
    for (int i = 0; i < 64; i++)
        buffer[i] = i ^ 0xAA;
}

// 编码类型枚举
enum EncodingType
{
    ENCODING_UTF8,
    ENCODING_GBK,
    ENCODING_ENGLISH_ONLY
};

// 全局编码类型
EncodingType g_encoding = ENCODING_UTF8;

// 检测和设置控制台编码
EncodingType detectAndSetEncoding()
{
    UINT consoleCP = GetConsoleOutputCP();

    // 尝试设置UTF-8 (代码页65001)
    if (SetConsoleOutputCP(65001))
    {
        SetConsoleCP(65001);
        return ENCODING_UTF8;
    }

    // 尝试设置GBK (代码页936)
    if (SetConsoleOutputCP(936))
    {
        SetConsoleCP(936);
        return ENCODING_GBK;
    }

    // 如果都失败，使用英文
    return ENCODING_ENGLISH_ONLY;
}

// 多语言字符串
struct MultiLangString
{
    const char *utf8;
    const char *gbk;
    const char *english;

    const char *get() const
    {
        switch (g_encoding)
        {
        case ENCODING_UTF8:
            return utf8;
        case ENCODING_GBK:
            return gbk;
        case ENCODING_ENGLISH_ONLY:
            return english;
        default:
            return english;
        }
    }
};

// 定义多语言字符串常量
namespace Strings
{
    const MultiLangString WELCOME = {
        "欢迎使用ATM自动取款机系统",
        "\xbb\xb6\xd3\xad\xca\xb9\xd3\xc3ATM\xd7\xd4\xb6\xaf\xc8\xa1\xbf\xee\xbb\xfa\xcf\xb5\xcd\xb3", // GBK编码
        "Welcome to ATM System"};

    const MultiLangString MAIN_MENU = {
        "主菜单",
        "\xd6\xf7\xb2\xcb\xb5\xa5",
        "Main Menu"};

    const MultiLangString VIEW_BALANCE = {
        "查看余额",
        "\xb2\xe9\xbf\xb4\xd3\xe0\xb6\xee",
        "View Balance"};

    const MultiLangString WITHDRAW = {
        "取款",
        "\xc8\xa1\xbf\xee",
        "Withdraw"};

    const MultiLangString DEPOSIT = {
        "存款",
        "\xb4\xe6\xbf\xee",
        "Deposit"};

    const MultiLangString TRANSFER = {
        "转账",
        "\xd7\xaa\xd5\xcb",
        "Transfer"};

    const MultiLangString CHANGE_PASSWORD = {
        "修改密码",
        "\xd0\xde\xb8\xc4\xc3\xdc\xc2\xeb",
        "Change Password"};

    const MultiLangString EXIT = {
        "退卡",
        "\xcd\xcb\xbf\xa8",
        "Exit"};

    const MultiLangString ACCOUNT_NOT_EXIST = {
        "账号不存在！",
        "\xd5\xcb\xba\xc5\xb2\xbb\xb4\xe6\xd4\xda\xa3\xa1",
        "Account does not exist!"};

    const MultiLangString ACCOUNT_LOCKED = {
        "该账户已被锁定，请联系银行！",
        "\xb8\xc3\xd5\xcb\xbb\xa7\xd2\xd1\xb1\xbb\xcb\xf8\xb6\xa8\xa3\xac\xc7\xeb\xc1\xaa\xcf\xb5\xd2\xf8\xd0\xd0\xa3\xa1",
        "Account is locked. Please contact the bank!"};

    const MultiLangString LOGIN_SUCCESS = {
        "登录成功！",
        "\xb5\xc7\xc2\xbc\xb3\xc9\xb9\xa6\xa3\xa1",
        "Login successful!"};

    const MultiLangString PASSWORD_ERROR = {
        "密码错误！",
        "\xc3\xdc\xc2\xeb\xb4\xed\xce\xf3\xa3\xa1",
        "Wrong password!"};

    const MultiLangString ENCODING_WARNING = {
        "",
        "",
        "Warning: Console does not support UTF-8 or GBK. Using English only."};

    const MultiLangString NEW_ACCOUNT_DETECTED = {
        "检测到新账号，是否创建？",
        "\xbc\xec\xb2\xe2\xb5\xbd\xd0\xc2\xd5\xcb\xba\xc5\xa3\xac\xca\xc7\xb7\xf1\xb4\xb4\xbd\xa8\xa3\xbf",
        "New account detected. Create it?"};

    const MultiLangString CONFIRM_ACCOUNT = {
        "请再次输入账号确认: ",
        "\xc7\xeb\xd4\xd9\xb4\xce\xca\xe4\xc8\xeb\xd5\xcb\xba\xc5\xc8\xb7\xc8\xcf: ",
        "Please re-enter account number: "};

    const MultiLangString ACCOUNT_MISMATCH = {
        "两次输入的账号不一致！",
        "\xc1\xbd\xb4\xce\xca\xe4\xc8\xeb\xb5\xc4\xd5\xcb\xba\xc5\xb2\xbb\xd2\xbb\xd6\xc2\xa3\xa1",
        "Account numbers do not match!"};

    const MultiLangString ENTER_NAME = {
        "请输入姓名: ",
        "\xc7\xeb\xca\xe4\xc8\xeb\xd0\xd5\xc3\xfb: ",
        "Enter name: "};

    const MultiLangString ENTER_ID_CARD = {
        "请输入18位身份证号: ",
        "\xc7\xeb\xca\xe4\xc8\xeb18\xce\xbb\xc9\xed\xb7\xdd\xd6\xa4\xba\xc5: ",
        "Enter 18-digit ID card number: "};

    const MultiLangString ENTER_PASSWORD = {
        "请设置6位密码: ",
        "\xc7\xeb\xc9\xe8\xd6\xc36\xce\xbb\xc3\xdc\xc2\xeb: ",
        "Set 6-digit password: "};

    const MultiLangString CONFIRM_PASSWORD = {
        "请再次确认密码: ",
        "\xc7\xeb\xd4\xd9\xb4\xce\xc8\xb7\xc8\xcf\xc3\xdc\xc2\xeb: ",
        "Confirm password: "};

    const MultiLangString PASSWORD_MISMATCH = {
        "两次输入的密码不一致！",
        "\xc1\xbd\xb4\xce\xca\xe4\xc8\xeb\xb5\xc4\xc3\xdc\xc2\xeb\xb2\xbb\xd2\xbb\xd6\xc2\xa3\xa1",
        "Passwords do not match!"};

    const MultiLangString INITIAL_BALANCE = {
        "请输入初始余额: ¥",
        "\xc7\xeb\xca\xe4\xc8\xeb\xb3\xf5\xca\xbc\xd3\xe0\xb6\xee: \xa1\xe3",
        "Enter initial balance: ¥"};

    const MultiLangString ACCOUNT_CREATED = {
        "账号创建成功！",
        "\xd5\xcb\xba\xc5\xb4\xb4\xbd\xa8\xb3\xc9\xb9\xa6\xa3\xa1",
        "Account created successfully!"};
}

// 全局内存加密密钥（混淆存储，运行时解密）
static unsigned char MEMORY_KEY_OBFUSCATED[32] = {
    0x71, 0x24, 0x4f, 0x4c, 0x72, 0xe4, 0x88, 0xfc,
    0xf1, 0xad, 0x4f, 0xd2, 0x53, 0x85, 0x05, 0x66,
    0x2c, 0x74, 0x2b, 0x3a, 0xa9, 0xd1, 0x07, 0xff,
    0x30, 0x22, 0x07, 0xca, 0x0f, 0x43, 0x46, 0xa4};
static unsigned char MEMORY_KEY[32];
static bool keyInitialized = false;

// 运行时密钥初始化（带反调试检测）
void initializeKey()
{
    if (keyInitialized)
        return;

    // 反调试检测
    if (AntiDebug::detect())
    {
        AntiDebug::respond();
    }

    // 解密密钥
    for (int i = 0; i < 32; i++)
    {
        MEMORY_KEY[i] = MEMORY_KEY_OBFUSCATED[i] ^ 0x5A;
    }

    keyInitialized = true;
    fakeFunction1();
}

// AES加密函数（使用ECB模式，带混淆）
string encryptAES(const string &plaintext)
{
    // 反调试检测
    if (AntiDebug::detect())
    {
        AntiDebug::respond();
    }

    initializeKey(); // 确保密钥已初始化

    if (plaintext.empty())
        return "";

    // 虚假分支
    volatile int obfuscate = rand() % 2;
    if (obfuscate > 10)
    {
        fakeFunction2();
        return "";
    }

    // 计算需要的填充
    int padding = AES_BLOCK_SIZE - (plaintext.length() % AES_BLOCK_SIZE);
    string padded = plaintext + string(padding, (char)padding);

    unsigned char *encrypted = new unsigned char[padded.length()];
    AES_KEY encryptKey;
    AES_set_encrypt_key(MEMORY_KEY, 256, &encryptKey);

    // 分块加密
    for (size_t i = 0; i < padded.length(); i += AES_BLOCK_SIZE)
    {
        AES_encrypt((unsigned char *)padded.c_str() + i, encrypted + i, &encryptKey);
    }

    // 转换为十六进制字符串
    stringstream ss;
    for (size_t i = 0; i < padded.length(); i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)encrypted[i];
    }

    delete[] encrypted;
    return ss.str();
}

// AES解密函数（带混淆）
string decryptAES(const string &ciphertext)
{
    initializeKey(); // 确保密钥已初始化

    // 周期性反调试检测
    static int decryptCount = 0;
    if (++decryptCount % 10 == 0 && AntiDebug::detect())
    {
        AntiDebug::respond();
    }

    if (ciphertext.empty())
        return "";

    if (ciphertext.length() % 2 != 0)
        return "";

    // 从十六进制转换回字节
    int len = ciphertext.length() / 2;
    unsigned char *encrypted = new unsigned char[len];
    for (int i = 0; i < len; i++)
    {
        sscanf(ciphertext.substr(i * 2, 2).c_str(), "%2hhx", &encrypted[i]);
    }

    unsigned char *decrypted = new unsigned char[len];
    AES_KEY decryptKey;
    AES_set_decrypt_key(MEMORY_KEY, 256, &decryptKey);

    // 分块解密
    for (int i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        AES_decrypt(encrypted + i, decrypted + i, &decryptKey);
    }

    // 移除填充
    int padding = decrypted[len - 1];
    string result((char *)decrypted, len - padding);

    delete[] encrypted;
    delete[] decrypted;

    return result;
}

// 在内存中以加密形式存储敏感数据
class SecureString
{
private:
    string encryptedData;

public:
    SecureString() : encryptedData("") {}

    SecureString(const string &plaintext)
    {
        set(plaintext);
    }

    // 设置值（加密存储）
    void set(const string &plaintext)
    {
        encryptedData = encryptAES(plaintext);
    }

    // 获取值（临时解密）
    string get() const
    {
        return decryptAES(encryptedData);
    }

    // 获取加密数据（用于持久化）- 直接返回加密数据，不解密
    string getEncrypted() const
    {
        return encryptedData;
    }

    // 从加密数据加载 - 直接设置加密数据，不加密
    void setEncrypted(const string &encrypted)
    {
        encryptedData = encrypted;
    }

    // 设置原始值（不加密，直接存储）- 用于加载已加密的哈希值
    void setRaw(const string &rawData)
    {
        encryptedData = rawData;
    }

    // 获取原始值（不解密）- 用于保存已加密的哈希值
    string getRaw() const
    {
        return encryptedData;
    }

    // 比较（临时解密后比较）
    bool equals(const string &other) const
    {
        return get() == other;
    }

    // 清空
    void clear()
    {
        encryptedData.clear();
    }
};

// SHA256哈希函数（带混淆）
string calculateSHA256(const string &input)
{
    // 虚假操作混淆
    volatile int dummy = input.length() * 13 + 7;
    if (dummy < 0)
        fakeFunction1();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// 交易记录结构
struct Transaction
{
    string date;
    string type;
    double amount;
    double balance;
};

// 银行账户类
class BankAccount
{
private:
    SecureString accountNumber;       // 19位账号
    SecureString name;                // 姓名
    SecureString idCard;              // 18位身份证
    SecureString passwordHash;        // 密码的SHA256哈希值
    double balance;                   // 余额
    bool isLocked;                    // 是否锁定
    vector<Transaction> transactions; // 交易记录
    double dailyWithdrawn;            // 今日已取款金额
    string lastWithdrawDate;          // 最后取款日期

public:
    BankAccount() : balance(10000.0), isLocked(false), dailyWithdrawn(0.0) {}

    BankAccount(string acc, string n, string id, string pwd, double bal = 10000.0)
        : balance(bal), isLocked(false), dailyWithdrawn(0.0)
    {
        accountNumber.set(acc);
        name.set(n);
        idCard.set(id);
        passwordHash.set(calculateSHA256(pwd));
    }

    // Getter方法（临时解密）
    string getAccountNumber() const { return accountNumber.get(); }
    string getName() const { return name.get(); }
    double getBalance() const { return balance; }
    bool getIsLocked() const { return isLocked; }

    // 验证密码（计算输入密码的SHA256并与存储的哈希值比对）
    bool verifyPassword(const string &pwd) const
    {
        string inputHash = calculateSHA256(pwd);
        return passwordHash.equals(inputHash);
    }

    // 锁定账户
    void lockAccount()
    {
        isLocked = true;
    }

    // 修改密码（验证旧密码哈希，存储新密码哈希）
    bool changePassword(const string &oldPwd, const string &newPwd)
    {
        if (verifyPassword(oldPwd) && newPwd.length() == 6)
        {
            passwordHash.set(calculateSHA256(newPwd));
            return true;
        }
        return false;
    }

    // 查询余额
    double queryBalance() const
    {
        return balance;
    }

    // 取款
    bool withdraw(double amount)
    {
        // 检查是否为100的整数倍
        if (fmod(amount, 100.0) != 0)
        {
            return false;
        }

        // 单笔限额5000元
        if (amount > 5000)
        {
            cout << "单笔取款金额不能超过5000元！" << endl;
            return false;
        }

        // 检查日期，重置每日取款额度
        string today = getCurrentDate();
        if (today != lastWithdrawDate)
        {
            dailyWithdrawn = 0;
            lastWithdrawDate = today;
        }

        // 单日限额20000元
        if (dailyWithdrawn + amount > 20000)
        {
            cout << "今日取款金额已达到限额（20000元）！" << endl;
            return false;
        }

        if (amount > balance)
        {
            cout << "余额不足！" << endl;
            return false;
        }

        balance -= amount;
        dailyWithdrawn += amount;

        // 记录交易
        Transaction trans;
        trans.date = today;
        trans.type = "取款";
        trans.amount = amount;
        trans.balance = balance;
        transactions.push_back(trans);

        return true;
    }

    // 存款
    bool deposit(double amount)
    {
        if (amount <= 0)
        {
            return false;
        }

        balance += amount;

        // 记录交易
        Transaction trans;
        trans.date = getCurrentDate();
        trans.type = "存款";
        trans.amount = amount;
        trans.balance = balance;
        transactions.push_back(trans);

        return true;
    }

    // 转账（转出）
    bool transfer(double amount)
    {
        if (amount <= 0 || amount > balance)
        {
            return false;
        }

        balance -= amount;

        // 记录交易
        Transaction trans;
        trans.date = getCurrentDate();
        trans.type = "转账";
        trans.amount = amount;
        trans.balance = balance;
        transactions.push_back(trans);

        return true;
    }

    // 转账（转入）
    void receiveTransfer(double amount)
    {
        balance += amount;

        // 记录交易
        Transaction trans;
        trans.date = getCurrentDate();
        trans.type = "转入";
        trans.amount = amount;
        trans.balance = balance;
        transactions.push_back(trans);
    }

    // 获取当前日期
    string getCurrentDate() const
    {
        time_t now = time(0);
        tm *ltm = localtime(&now);
        stringstream ss;
        ss << (1900 + ltm->tm_year) << "-"
           << setfill('0') << setw(2) << (1 + ltm->tm_mon) << "-"
           << setfill('0') << setw(2) << ltm->tm_mday;
        return ss.str();
    }

    // 保存到文件（密码哈希以加密形式保存，其他字段解密后保存）
    void saveToFile(ofstream &out, int accountIndex) const
    {
        out << "\n[账户 " << accountIndex << "]" << endl;
        out << "账号: " << accountNumber.get() << endl;
        out << "姓名: " << name.get() << endl;
        out << "身份证: " << idCard.get() << endl;
        // 直接存储加密的哈希值，不解密
        out << "密码哈希(SHA256): " << passwordHash.getRaw() << endl;
        out << "余额: " << fixed << setprecision(2) << balance << endl;
        out << "账户状态: " << (isLocked ? "锁定" : "正常") << endl;
        out << "今日已取款: " << fixed << setprecision(2) << dailyWithdrawn << endl;
        out << "最后取款日期: " << lastWithdrawDate << endl;

        // 保存交易记录
        out << "\n--- 交易记录 (共" << transactions.size() << "条) ---" << endl;
        for (size_t i = 0; i < transactions.size(); i++)
        {
            out << "  [" << (i + 1) << "] ";
            out << transactions[i].date << " | ";
            out << transactions[i].type << " | ";
            out << "金额: ¥" << fixed << setprecision(2) << transactions[i].amount << " | ";
            out << "余额: ¥" << fixed << setprecision(2) << transactions[i].balance << endl;
        }
    }

    // 从文件读取（密码哈希以加密形式读取）
    bool loadFromFile(ifstream &in)
    {
        string line;
        DEBUG_LOG("进入 loadFromFile");

        try
        {
            // 读取账户标题行 [账户 N]
            if (!getline(in, line))
            {
                DEBUG_LOG("读取账户标题行失败");
                return false;
            }
            DEBUG_LOG("账户标题行: " + line);

            // 读取账号
            if (!getline(in, line))
            {
                DEBUG_LOG("读取账号行失败");
                return false;
            }
            size_t pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("账号行缺少冒号分隔符: " + line);
                return false;
            }
            accountNumber.set(line.substr(pos + 2));
            DEBUG_LOG("账号: " + line.substr(pos + 2));

            // 读取姓名
            if (!getline(in, line))
            {
                DEBUG_LOG("读取姓名行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("姓名行缺少冒号分隔符: " + line);
                return false;
            }
            name.set(line.substr(pos + 2));
            DEBUG_LOG("姓名: " + line.substr(pos + 2));

            // 读取身份证
            if (!getline(in, line))
            {
                DEBUG_LOG("读取身份证行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("身份证行缺少冒号分隔符: " + line);
                return false;
            }
            idCard.set(line.substr(pos + 2));
            DEBUG_LOG("身份证: " + line.substr(pos + 2));

            // 读取密码哈希 - 直接存储加密的哈希值，不加密
            if (!getline(in, line))
            {
                DEBUG_LOG("读取密码哈希行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("密码哈希行缺少冒号分隔符: " + line);
                return false;
            }
            passwordHash.setRaw(line.substr(pos + 2));
            DEBUG_LOG("密码哈希: " + line.substr(pos + 2).substr(0, 20) + "...");

            // 读取余额
            if (!getline(in, line))
            {
                DEBUG_LOG("读取余额行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("余额行缺少冒号分隔符: " + line);
                return false;
            }
            try
            {
                balance = stod(line.substr(pos + 2));
                DEBUG_LOG("余额: " + to_string(balance));
            }
            catch (...)
            {
                DEBUG_LOG("余额转换失败: " + line.substr(pos + 2));
                return false;
            }

            // 读取账户状态
            if (!getline(in, line))
            {
                DEBUG_LOG("读取账户状态行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("账户状态行缺少冒号分隔符: " + line);
                return false;
            }
            string status = line.substr(pos + 2);
            DEBUG_LOG("账户状态: " + status);
            isLocked = (status == "锁定");
            DEBUG_LOG(isLocked ? "账户已锁定" : "账户正常");

            // 读取今日已取款
            if (!getline(in, line))
            {
                DEBUG_LOG("读取今日已取款行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("今日已取款行缺少冒号分隔符: " + line);
                return false;
            }
            try
            {
                dailyWithdrawn = stod(line.substr(pos + 2));
                DEBUG_LOG("今日已取款: " + to_string(dailyWithdrawn));
            }
            catch (...)
            {
                DEBUG_LOG("今日已取款转换失败: " + line.substr(pos + 2));
                return false;
            }

            // 读取最后取款日期
            if (!getline(in, line))
            {
                DEBUG_LOG("读取最后取款日期行失败");
                return false;
            }
            pos = line.find(": ");
            if (pos == string::npos)
            {
                DEBUG_LOG("最后取款日期行缺少冒号分隔符: " + line);
                return false;
            }
            lastWithdrawDate = line.substr(pos + 2);
            DEBUG_LOG("最后取款日期: " + lastWithdrawDate);

            // 读取空行
            getline(in, line);

            // 读取交易记录标题行
            if (!getline(in, line))
                return true; // 交易记录可能为空

            // 解析交易记录数量
            size_t pos1 = line.find("共");
            size_t pos2 = line.find("条");
            if (pos1 != string::npos && pos2 != string::npos)
            {
                int count = stoi(line.substr(pos1 + 3, pos2 - pos1 - 3));

                // 读取每条交易记录
                for (int i = 0; i < count; i++)
                {
                    if (!getline(in, line))
                        break;
                    if (line.empty())
                        continue;

                    Transaction trans;

                    // 解析格式: [N] 日期 | 类型 | 金额: ¥X.XX | 余额: ¥Y.YY
                    size_t dateStart = line.find("]") + 2;
                    size_t dateEnd = line.find(" | ", dateStart);
                    if (dateEnd == string::npos)
                        continue;
                    trans.date = line.substr(dateStart, dateEnd - dateStart);

                    size_t typeStart = dateEnd + 3;
                    size_t typeEnd = line.find(" | ", typeStart);
                    if (typeEnd == string::npos)
                        continue;
                    trans.type = line.substr(typeStart, typeEnd - typeStart);

                    size_t amountStart = line.find("¥", typeEnd);
                    if (amountStart == string::npos)
                        continue;
                    amountStart += 3;
                    size_t amountEnd = line.find(" | ", amountStart);
                    if (amountEnd == string::npos)
                        continue;
                    trans.amount = stod(line.substr(amountStart, amountEnd - amountStart));

                    size_t balanceStart = line.find("¥", amountEnd);
                    if (balanceStart == string::npos)
                        continue;
                    balanceStart += 3;
                    trans.balance = stod(line.substr(balanceStart));

                    transactions.push_back(trans);
                }
            }

            return true;
        }
        catch (...)
        {
            // 捕获所有异常，返回false
            DEBUG_LOG("loadFromFile 异常");
            return false;
        }
    }
};

// ATM系统类
class ATMSystem
{
private:
    vector<BankAccount> accounts;
    BankAccount *currentAccount;
    string dataFile;

    // 验证账号格式（19位数字）
    bool isValidAccountNumber(const string &accNum) const
    {
        if (accNum.length() != 19)
            return false;
        for (char c : accNum)
        {
            if (!isdigit(c))
                return false;
        }
        return true;
    }

public:
    ATMSystem() : currentAccount(nullptr), dataFile("accounts.dat")
    {
        // 初始化密钥和反调试检测
        initializeKey();

        // 反调试检测
        if (AntiDebug::detect())
        {
            AntiDebug::respond();
        }

        // 虚假代码
        volatile int security_check = 0x12345678;
        security_check ^= 0xABCDEF00;

        loadAccounts();
    }

    ~ATMSystem()
    {
        try
        {
            saveAccounts();
        }
        catch (...)
        {
            // 析构函数中不应该抛出异常，静默处理
        }
    }

    // 加载账户数据
    bool loadAccounts()
    {
        ifstream in(dataFile);
        if (!in.is_open())
        {
            // 文件不存在不是错误，可能是首次运行
            DEBUG_LOG("账户数据文件不存在，可能是首次运行。");
            return true;
        }
        DEBUG_LOG("成功打开账户数据文件。");

        try
        {
            string line;

            // 读取文件头部
            if (!getline(in, line))
            {
                in.close();
                return false;
            }
            // 验证文件头
            if (line.find("ATM账户数据文件") == string::npos)
            {
                DEBUG_LOG("文件头验证失败，无效的文件格式。");
                in.close();
                return false;
            }
            DEBUG_LOG("文件头验证通过。");

            // 读取时间行
            if (!getline(in, line))
            {
                in.close();
                return false;
            }

            // 读取账户数量行
            if (!getline(in, line))
            {
                in.close();
                return false;
            }

            // 解析账户数量
            int count = 0;
            size_t pos = line.find(": ");
            if (pos == string::npos)
            {
                in.close();
                return false;
            }
            try
            {
                count = stoi(line.substr(pos + 2));
                DEBUG_LOG("账户数量: " + to_string(count));
            }
            catch (...)
            {
                DEBUG_LOG("账户数量转换失败: " + line.substr(pos + 2));
                in.close();
                return false;
            }

            // 读取空行
            if (!getline(in, line))
            {
                in.close();
                return false;
            }

            // 读取分隔线
            if (!getline(in, line))
            {
                in.close();
                return false;
            }

            // 读取空行（分隔线后的空行）
            if (!getline(in, line))
            {
                in.close();
                return false;
            }
            if (!line.empty())
            {
                // 如果没有空行，可能是旧格式，将当前行视为账户标题行？这里我们退回一个字符？
                // 但为了安全，我们假定文件格式正确，直接使用当前行作为账户标题行
                // 我们将行放回流中很困难，所以暂时忽略此检查。
            }

            // 读取每个账户
            for (int i = 0; i < count; i++)
            {
                DEBUG_LOG("正在加载账户 " + to_string(i + 1) + " ...");
                BankAccount acc;
                if (!acc.loadFromFile(in))
                {
                    DEBUG_LOG("加载账户 " + to_string(i + 1) + " 失败。");
                    in.close();
                    return false;
                }
                accounts.push_back(acc);
                DEBUG_LOG("账户 " + to_string(i + 1) + " 加载成功。");
            }

#ifdef DEBUG_LOADING
            DEBUG_LOG("成功加载 " + to_string(accounts.size()) + " 个账户。");
            for (size_t i = 0; i < accounts.size(); i++)
            {
                DEBUG_LOG("账户 " + to_string(i) + ": " + accounts[i].getAccountNumber());
            }
#endif

            in.close();
            return true;
        }
        catch (...)
        {
            in.close();
            return false;
        }
    }

    // 保存账户数据（使用临时文件模式，防止数据丢失）
    bool saveAccounts()
    {
        // 使用临时文件
        string tempFile = dataFile + ".tmp";

        try
        {
            ofstream out(tempFile);
            if (!out.is_open())
            {
                cout << "无法创建临时数据文件！" << endl;
                return false;
            }

            // 文件头部
            out << "==================== ATM账户数据文件 ====================" << endl;
            out << "文件生成时间: " << getCurrentDateTime() << endl;
            out << "账户数量: " << accounts.size() << endl;
            out << "\n==================== 账户信息 ====================" << endl;

            // 保存每个账户
            for (size_t i = 0; i < accounts.size(); i++)
            {
                accounts[i].saveToFile(out, i + 1);
            }

            out << "\n==================== 文件结束 ====================" << endl;

            // 检查写入是否成功
            if (!out.good())
            {
                out.close();
                cout << "写入数据文件失败！" << endl;
                return false;
            }

            out.close();

            // 在Windows上，需要先删除原文件（如果存在）
            remove(dataFile.c_str());

            // 重命名临时文件为正式文件
            if (rename(tempFile.c_str(), dataFile.c_str()) != 0)
            {
                cout << "保存数据文件失败！" << endl;
                return false;
            }

            return true;
        }
        catch (...)
        {
            cout << "保存数据文件时发生异常！" << endl;
            // 尝试删除临时文件
            remove(tempFile.c_str());
            return false;
        }
    }

    // 获取当前日期时间
    string getCurrentDateTime() const
    {
        time_t now = time(0);
        tm *ltm = localtime(&now);
        stringstream ss;
        ss << (1900 + ltm->tm_year) << "-"
           << setfill('0') << setw(2) << (1 + ltm->tm_mon) << "-"
           << setfill('0') << setw(2) << ltm->tm_mday << " "
           << setfill('0') << setw(2) << ltm->tm_hour << ":"
           << setfill('0') << setw(2) << ltm->tm_min << ":"
           << setfill('0') << setw(2) << ltm->tm_sec;
        return ss.str();
    }

    // 创建新账户
    bool createNewAccount(const string &accountNumber)
    {
        cout << "\n"
             << Strings::NEW_ACCOUNT_DETECTED.get() << " (Y/N): ";
        char confirm;
        cin >> confirm;

        if (confirm != 'Y' && confirm != 'y')
        {
            return false;
        }

        // 验证账号格式
        if (!isValidAccountNumber(accountNumber))
        {
            if (g_encoding != ENCODING_ENGLISH_ONLY)
            {
                cout << "账号必须是19位数字！" << endl;
            }
            else
            {
                cout << "Account number must be 19 digits!" << endl;
            }
            Sleep(2000);
            return false;
        }

        // 要求再次输入账号确认
        string accountNumber2;
        cout << Strings::CONFIRM_ACCOUNT.get();
        cin >> accountNumber2;

        if (accountNumber != accountNumber2)
        {
            cout << Strings::ACCOUNT_MISMATCH.get() << endl;
            Sleep(2000);
            return false;
        }

        // 输入姓名
        string name;
        cout << Strings::ENTER_NAME.get();
        cin.ignore();
        getline(cin, name);

        // 输入身份证号
        string idCard;
        cout << Strings::ENTER_ID_CARD.get();
        cin >> idCard;

        if (idCard.length() != 18)
        {
            if (g_encoding != ENCODING_ENGLISH_ONLY)
            {
                cout << "身份证号必须是18位！" << endl;
            }
            else
            {
                cout << "ID card number must be 18 digits!" << endl;
            }
            Sleep(2000);
            return false;
        }

        // 输入密码
        string password1, password2;
        cout << Strings::ENTER_PASSWORD.get();
        cin >> password1;

        if (password1.length() != 6)
        {
            if (g_encoding != ENCODING_ENGLISH_ONLY)
            {
                cout << "密码必须是6位！" << endl;
            }
            else
            {
                cout << "Password must be 6 digits!" << endl;
            }
            Sleep(2000);
            return false;
        }

        cout << Strings::CONFIRM_PASSWORD.get();
        cin >> password2;

        if (password1 != password2)
        {
            cout << Strings::PASSWORD_MISMATCH.get() << endl;
            Sleep(2000);
            return false;
        }

        // 输入初始余额
        double initialBalance;
        cout << Strings::INITIAL_BALANCE.get();
        cin >> initialBalance;

        if (initialBalance < 0)
        {
            if (g_encoding != ENCODING_ENGLISH_ONLY)
            {
                cout << "初始余额不能为负数！" << endl;
            }
            else
            {
                cout << "Initial balance cannot be negative!" << endl;
            }
            Sleep(2000);
            return false;
        }

        // 创建新账户
        BankAccount newAccount(accountNumber, name, idCard, password1, initialBalance);
        accounts.push_back(newAccount);
        if (!saveAccounts())
        {
            accounts.pop_back(); // 保存失败，移除刚添加的账户
            return false;
        }

        cout << "\n"
             << Strings::ACCOUNT_CREATED.get() << endl;
        Sleep(2000);

        return true;
    }

    // 查找账户
    BankAccount *findAccount(const string &accountNumber)
    {
#ifdef DEBUG_LOADING
        DEBUG_LOG("查找账户: " + accountNumber);
        DEBUG_LOG("当前账户数量: " + to_string(accounts.size()));
        for (size_t i = 0; i < accounts.size(); i++)
        {
            string loadedAcc = accounts[i].getAccountNumber();
            DEBUG_LOG("账户 " + to_string(i) + ": " + loadedAcc + " (长度: " + to_string(loadedAcc.length()) + ")");
        }
#endif
        for (auto &acc : accounts)
        {
            string loadedAcc = acc.getAccountNumber();
#ifdef DEBUG_LOADING
            DEBUG_LOG("比较: 输入='" + accountNumber + "' 加载='" + loadedAcc + "'");
#endif
            if (loadedAcc == accountNumber)
            {
#ifdef DEBUG_LOADING
                DEBUG_LOG("找到匹配账户！");
#endif
                return &acc;
            }
        }
#ifdef DEBUG_LOADING
        DEBUG_LOG("未找到匹配账户。");
#endif
        return nullptr;
    }

    // 显示欢迎界面
    void showWelcome()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "       " << Strings::WELCOME.get() << "        " << endl;
        cout << "========================================" << endl;
        cout << endl;
    }

    // 用户登录
    bool login()
    {
        showWelcome();

        string accountNumber;
        cout << "请插卡（输入19位账号）: ";
        cin >> accountNumber;

        // 验证账号格式
        if (!isValidAccountNumber(accountNumber))
        {
            if (g_encoding != ENCODING_ENGLISH_ONLY)
            {
                cout << "账号必须是19位数字！" << endl;
            }
            else
            {
                cout << "Account number must be 19 digits!" << endl;
            }
            Sleep(2000);
            return false;
        }

        currentAccount = findAccount(accountNumber);

        if (currentAccount == nullptr)
        {
            // 账号不存在，尝试创建新账号
            if (createNewAccount(accountNumber))
            {
                // 创建成功后，重新查找账户
                currentAccount = findAccount(accountNumber);
                if (currentAccount == nullptr)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        if (currentAccount->getIsLocked())
        {
            cout << Strings::ACCOUNT_LOCKED.get() << endl;
            Sleep(2000);
            currentAccount = nullptr;
            return false;
        }

        // 密码验证，最多3次机会
        int attempts = 0;
        while (attempts < 3)
        {
            string password;
            cout << "请输入6位密码: ";
            cin >> password;

            if (currentAccount->verifyPassword(password))
            {
                cout << Strings::LOGIN_SUCCESS.get() << endl;
                Sleep(1000);
                return true;
            }
            else
            {
                attempts++;
                if (attempts < 3)
                {
                    cout << Strings::PASSWORD_ERROR.get();
                    if (g_encoding != ENCODING_ENGLISH_ONLY)
                    {
                        cout << "您还有 " << (3 - attempts) << " 次机会。";
                    }
                    else
                    {
                        cout << " You have " << (3 - attempts) << " attempts left.";
                    }
                    cout << endl;
                }
                else
                {
                    if (g_encoding != ENCODING_ENGLISH_ONLY)
                    {
                        cout << "密码错误次数过多，账户已被锁定！" << endl;
                    }
                    else
                    {
                        cout << "Too many failed attempts. Account locked!" << endl;
                    }
                    currentAccount->lockAccount();
                    Sleep(2000);
                    currentAccount = nullptr;
                    return false;
                }
            }
        }

        return false;
    }

    // 显示主菜单
    void showMainMenu()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "              " << Strings::MAIN_MENU.get() << "                    " << endl;
        cout << "========================================" << endl;
        cout << "  1 - " << Strings::VIEW_BALANCE.get() << endl;
        cout << "  2 - " << Strings::WITHDRAW.get() << endl;
        cout << "  3 - " << Strings::DEPOSIT.get() << endl;
        cout << "  4 - " << Strings::TRANSFER.get() << endl;
        cout << "  5 - " << Strings::CHANGE_PASSWORD.get() << endl;
        cout << "  6 - " << Strings::EXIT.get() << endl;
        cout << "========================================" << endl;
        cout << (g_encoding == ENCODING_ENGLISH_ONLY ? "Enter a choice: " : "请选择操作: ");
    }

    // 查看余额
    void viewBalance()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "              余额查询                  " << endl;
        cout << "========================================" << endl;
        cout << "账户: " << currentAccount->getAccountNumber() << endl;
        cout << "姓名: " << currentAccount->getName() << endl;
        cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
        cout << "========================================" << endl;
        cout << "输入 0 返回主菜单: ";
        int returnChoice;
        cin >> returnChoice;
    }

    // 取款
    void withdrawCash()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "              取款                      " << endl;
        cout << "========================================" << endl;
        cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
        cout << "单笔限额: ¥5000.00" << endl;
        cout << "单日限额: ¥20000.00" << endl;
        cout << "========================================" << endl;
        cout << "请输入取款金额（100的整数倍，输入0返回）: ¥";
        double amount;
        cin >> amount;

        if (amount == 0)
        {
            return;
        }

        if (currentAccount->withdraw(amount))
        {
            cout << "取款成功！" << endl;
            cout << "取款金额: ¥" << amount << endl;
            cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
            if (!saveAccounts())
            {
                cout << "警告：数据保存失败，请尽快联系管理员！" << endl;
            }
        }
        else
        {
            cout << "取款失败！请检查金额是否为100的整数倍。" << endl;
        }

        cout << "按任意键返回主菜单...";
        cin.ignore();
        cin.get();
    }

    // 存款
    void depositFunds()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "              存款                      " << endl;
        cout << "========================================" << endl;
        cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
        cout << "========================================" << endl;
        cout << "请输入存款金额（输入0返回）: ¥";
        double amount;
        cin >> amount;

        if (amount == 0)
        {
            return;
        }

        if (currentAccount->deposit(amount))
        {
            cout << "存款成功！" << endl;
            cout << "存款金额: ¥" << amount << endl;
            cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
            if (!saveAccounts())
            {
                cout << "警告：数据保存失败，请尽快联系管理员！" << endl;
            }
        }
        else
        {
            cout << "存款失败！请输入有效金额。" << endl;
        }

        cout << "按任意键返回主菜单...";
        cin.ignore();
        cin.get();
    }

    // 转账
    void transfer()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "              转账                      " << endl;
        cout << "========================================" << endl;
        cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
        cout << "========================================" << endl;

        string targetAccount1, targetAccount2;
        cout << "请输入目标账号（19位，输入0返回）: ";
        cin >> targetAccount1;

        if (targetAccount1 == "0")
        {
            return;
        }

        // 验证目标账号格式
        if (!isValidAccountNumber(targetAccount1))
        {
            if (g_encoding != ENCODING_ENGLISH_ONLY)
            {
                cout << "账号必须是19位数字！" << endl;
            }
            else
            {
                cout << "Account number must be 19 digits!" << endl;
            }
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        cout << "请再次确认目标账号: ";
        cin >> targetAccount2;

        if (targetAccount1 != targetAccount2)
        {
            cout << "两次输入的账号不一致！" << endl;
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        if (targetAccount1 == currentAccount->getAccountNumber())
        {
            cout << "不能转账到自己的账户！" << endl;
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        BankAccount *targetAcc = findAccount(targetAccount1);
        if (targetAcc == nullptr)
        {
            cout << "目标账户不存在！" << endl;
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        cout << "目标账户姓名: " << targetAcc->getName() << endl;
        cout << "请输入转账金额: ¥";
        double amount;
        cin >> amount;

        if (amount <= 0)
        {
            cout << "请输入有效金额！" << endl;
        }
        else if (amount > currentAccount->getBalance())
        {
            cout << "余额不足！" << endl;
        }
        else
        {
            currentAccount->transfer(amount);
            targetAcc->receiveTransfer(amount);
            cout << "转账成功！" << endl;
            cout << "转账金额: ¥" << amount << endl;
            cout << "当前余额: ¥" << fixed << setprecision(2) << currentAccount->getBalance() << endl;
            if (!saveAccounts())
            {
                cout << "警告：数据保存失败，请尽快联系管理员！" << endl;
            }
        }

        cout << "按任意键返回主菜单...";
        cin.ignore();
        cin.get();
    }

    // 修改密码
    void changePassword()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "              修改密码                  " << endl;
        cout << "========================================" << endl;

        string oldPassword;
        cout << "请输入原密码（输入0返回）: ";
        cin >> oldPassword;

        if (oldPassword == "0")
        {
            return;
        }

        if (!currentAccount->verifyPassword(oldPassword))
        {
            cout << "原密码错误！" << endl;
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        string newPassword1, newPassword2;
        cout << "请输入新密码（6位数字）: ";
        cin >> newPassword1;

        if (newPassword1.length() != 6)
        {
            cout << "密码必须是6位数字！" << endl;
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        cout << "请再次确认新密码: ";
        cin >> newPassword2;

        if (newPassword1 != newPassword2)
        {
            cout << "两次输入的密码不一致！" << endl;
            cout << "按任意键返回主菜单...";
            cin.ignore();
            cin.get();
            return;
        }

        if (currentAccount->changePassword(oldPassword, newPassword1))
        {
            cout << "密码修改成功！" << endl;
            if (!saveAccounts())
            {
                cout << "警告：数据保存失败，请尽快联系管理员！" << endl;
            }
        }
        else
        {
            cout << "密码修改失败！" << endl;
        }

        cout << "按任意键返回主菜单...";
        cin.ignore();
        cin.get();
    }

    // 退卡
    void exitATM()
    {
        system("cls");
        cout << "========================================" << endl;
        cout << "        感谢使用ATM自动取款机系统       " << endl;
        cout << "              请取卡！                  " << endl;
        cout << "========================================" << endl;
        if (!saveAccounts())
        {
            cout << "警告：数据保存失败，请尽快联系管理员！" << endl;
        }
        currentAccount = nullptr;
        Sleep(2000);
    }

    // 运行ATM系统
    void run()
    {
        while (true)
        {
            if (login())
            {
                bool loggedIn = true;
                while (loggedIn)
                {
                    showMainMenu();
                    int choice;
                    cin >> choice;

                    switch (choice)
                    {
                    case 1:
                        viewBalance();
                        break;
                    case 2:
                        withdrawCash();
                        break;
                    case 3:
                        depositFunds();
                        break;
                    case 4:
                        transfer();
                        break;
                    case 5:
                        changePassword();
                        break;
                    case 6:
                        exitATM();
                        loggedIn = false;
                        break;
                    default:
                        cout << "无效选择！请重新输入。" << endl;
                        Sleep(1000);
                    }
                }
            }

            // 询问是否继续
            cout << "\n是否继续使用ATM？(Y/N): ";
            char cont;
            cin >> cont;

            if (cont == 'N' || cont == 'n')
            {
                break;
            }
        }

        cout << "\n再见！" << endl;
    }
};

int main()
{
    // 初始化随机数生成器（用于混淆）
    srand((unsigned int)time(NULL));

    // 反调试检测
    if (AntiDebug::detect())
    {
        AntiDebug::respond();
    }

    // 虚假代码分支
    volatile int antiTamper = 0x5A5A5A5A;
    if (antiTamper == 0)
    {
        exit(-1);
    }

    // 检测并设置最佳编码
    g_encoding = detectAndSetEncoding();

    // 如果不支持中文编码，显示警告
    if (g_encoding == ENCODING_ENGLISH_ONLY)
    {
        cout << "========================================" << endl;
        cout << Strings::ENCODING_WARNING.get() << endl;
        cout << "========================================" << endl;
        Sleep(3000);
    }

    // 周期性反调试检测
    if (AntiDebug::detect())
    {
        AntiDebug::respond();
    }

    ATMSystem atm;
    atm.run();

    // 清理敏感内存
    memset(MEMORY_KEY, 0, 32);
}
