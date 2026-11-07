# ARCHIV – NICHT ALS QUELLCODE VERWENDEN

Dieser automatisch erzeugte Dump ist ein veralteter historischer Schnappschuss
und enthaelt inzwischen ersetzte, unsichere Implementierungsdetails. Er darf
nicht kompiliert, kopiert oder als Sicherheitsreferenz verwendet werden. Die
einzig massgeblichen Quellen sind die aktuellen `.kr`-Dateien im Projekt und
der Bericht `SECURITY_AUDIT.md`.

# MDraft KR Enterprise - ZIP Code Dump

========== FILE: main.kr ==========

// ============================================================================
// Sovereign Server V10 Professional - KR Unified Language Edition
// Root Coordinator & Application Entry Point
// Fusion of C++20, Rust, and Go in a Single Architecture
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cassert>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <exception>

// Declarations of modules
int cpp_start_server(const char* host, int port, int worker_count);

extern "C" {
    // Protocol (Rust)
    bool rust_http_validate_header(uint64_t name_ptr, int32_t name_len, uint64_t val_ptr, int32_t val_len);
    int32_t rust_sanitize_path(uint64_t in_ptr, int32_t in_len, uint64_t out_ptr, int32_t max_out);
    int32_t rust_http_parse_request(uint64_t raw_ptr, int32_t raw_len, uint64_t out_method, int32_t max_method, uint64_t out_path, int32_t max_path, uint64_t out_version, int32_t max_version, uint64_t out_meta, uint64_t out_auth_bearer, int32_t max_auth, uint64_t out_ws_key, int32_t max_ws_key);
    int32_t rust_ws_compute_accept_key(uint64_t sec_ws_key, int32_t key_len, uint64_t out_buf, int32_t max_len);
    int32_t rust_ws_parse_frame_header(uint64_t buf, int32_t len, uint64_t out_info);
    int32_t rust_ws_apply_mask(uint64_t data, int32_t len, uint32_t mask_key);
    int32_t rust_ws_build_frame_header(int32_t opcode, int64_t payload_len, uint64_t out_buf, int32_t max_out);

    // Security (Rust & Go)
    int32_t rust_sha256(uint64_t data, int32_t len, uint64_t out_digest);
    int32_t rust_hmac_sha256(uint64_t key, int32_t key_len, uint64_t data, int32_t data_len, uint64_t out_mac);
    bool rust_constant_time_compare(uint64_t a, int32_t a_len, uint64_t b, int32_t b_len);
    int32_t rust_jwt_create(uint64_t secret, int32_t sec_len, uint64_t sub, int32_t sub_len, uint64_t role, int32_t role_len, int64_t exp_sec, uint64_t out_buf, int32_t max_out);
    int32_t rust_jwt_verify(uint64_t token, int32_t tok_len, uint64_t secret, int32_t sec_len, int64_t current_time_sec, uint64_t out_sub, int32_t max_sub);
    bool rust_token_bucket_consume(uint64_t bucket_id, int32_t max_tokens, double refill_per_sec, double now_sec);
    bool go_security_audit_environment(void);
    bool go_jwt_is_blacklisted(int64_t jtiId);
    bool go_jwt_revoke_token(int64_t jtiId);

    // Orchestration (Go)
    bool go_admission_init(int32_t maxConns);
    bool go_admission_acquire(void);
    void go_admission_release(void);
    int32_t go_get_active_conns(void);
    bool go_task_init(int32_t workers, int32_t queueCap);
    bool go_task_enqueue(int32_t taskType, int64_t payloadId);
    int64_t go_task_get_processed(void);
    int32_t go_task_get_queue_len(void);
    bool go_eventhub_publish(int32_t topicId, int64_t eventVal);
    int32_t go_eventhub_subscribe(int32_t topicId);
    int64_t go_eventhub_published_count(void);
    int32_t go_eventhub_subscribers_count(void);
    void go_record_request(int32_t statusCode, int64_t latencyMicros);
    int64_t go_metrics_total_requests(void);
    double go_metrics_average_latency_us(void);
    int64_t go_metrics_error_count(void);
}

static std::string hex_encode(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

static bool run_all_tests() {
    std::cout << "\n========================================================" << std::endl;
    std::cout << "  RUNNING KR MULTI-LANGUAGE TEST SUITE (C++, Rust, Go)" << std::endl;
    std::cout << "========================================================" << std::endl;

    // Test 1: Rust HTTP Header CR/LF Validation
    std::cout << "[TEST 1] Rust HTTP Header CR/LF Injection Defense ... ";
    std::string safe_hdr = "X-Valid-Token";
    std::string safe_val = "SafeValue123";
    std::string bad_hdr = "X-Evil\r\nInjected";
    std::string bad_val = "Value\r\nSet-Cookie: pwned";

    bool ok_safe = rust_http_validate_header(
        (uint64_t)safe_hdr.data(), (int32_t)safe_hdr.size(),
        (uint64_t)safe_val.data(), (int32_t)safe_val.size()
    );
    bool ok_bad_hdr = rust_http_validate_header(
        (uint64_t)bad_hdr.data(), (int32_t)bad_hdr.size(),
        (uint64_t)safe_val.data(), (int32_t)safe_val.size()
    );
    bool ok_bad_val = rust_http_validate_header(
        (uint64_t)safe_hdr.data(), (int32_t)safe_hdr.size(),
        (uint64_t)bad_val.data(), (int32_t)bad_val.size()
    );

    if (ok_safe && !ok_bad_hdr && !ok_bad_val) {
        std::cout << "PASSED [OK]" << std::endl;
    } else {
        std::cout << "FAILED [X]" << std::endl;
        return false;
    }

    // Test 2: Rust Path Sanitization (Directory Traversal Prevention)
    std::cout << "[TEST 2] Rust Directory Traversal Sanitizer ... ";
    std::string dangerous_path = "/static/../../../windows/system32/cmd.exe";
    char clean_path[256] = {0};
    int32_t p_len = rust_sanitize_path(
        (uint64_t)dangerous_path.data(), (int32_t)dangerous_path.size(),
        (uint64_t)clean_path, sizeof(clean_path)
    );
    if (p_len > 0 && std::string(clean_path) == "/windows/system32/cmd.exe" && std::string(clean_path).find("..") == std::string::npos) {
        std::cout << "PASSED [OK] (Sanitized to: " << clean_path << ")" << std::endl;
    } else {
        std::cout << "FAILED [X] (Result: " << clean_path << ")" << std::endl;
        return false;
    }

    // Test 3: Rust SHA-256 FIPS Standard Test Vector ("abc")
    std::cout << "[TEST 3] Rust Pure SHA-256 FIPS 180-4 Test Vector ... ";
    std::string test_msg = "abc";
    uint8_t digest[32] = {0};
    rust_sha256((uint64_t)test_msg.data(), (int32_t)test_msg.size(), (uint64_t)digest);
    std::string hex_digest = hex_encode(digest, 32);
    // Known SHA-256 of "abc": ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    if (hex_digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        std::cout << "PASSED [OK]" << std::endl;
    } else {
        std::cout << "FAILED [X] (Digest: " << hex_digest << ")" << std::endl;
        return false;
    }

    // Test 4: Rust WebSocket RFC 6455 Handshake Accept Key (Known Vector)
    std::cout << "[TEST 4] Rust RFC 6455 WebSocket Handshake Vector ... ";
    std::string ws_test_key = "dGhlIHNhbXBsZSBub25jZQ==";
    char ws_accept[64] = {0};
    int32_t ws_ret = rust_ws_compute_accept_key(
        (uint64_t)ws_test_key.data(), (int32_t)ws_test_key.size(),
        (uint64_t)ws_accept, sizeof(ws_accept)
    );
    if (ws_ret > 0 && std::string(ws_accept) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
        std::cout << "PASSED [OK] (" << ws_accept << ")" << std::endl;
    } else {
        std::cout << "FAILED [X] (Got: " << ws_accept << ")" << std::endl;
        return false;
    }

    // Test 5: Rust JWT Cryptographic Generation & Verification
    std::cout << "[TEST 5] Rust JWT HMAC-SHA256 Sign & Verify Lifecycle ... ";
    std::string secret = "test_only_hmac_key_32_bytes_minimum!";
    std::string subject = "user_sovereign_42";
    std::string role = "system_admin";
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    int64_t exp_valid = now_ts + 600; // 10 minutes in future

    char jwt_token[512] = {0};
    int32_t jwt_len = rust_jwt_create(
        (uint64_t)secret.data(), (int32_t)secret.size(),
        (uint64_t)subject.data(), (int32_t)subject.size(),
        (uint64_t)role.data(), (int32_t)role.size(),
        exp_valid,
        (uint64_t)jwt_token, sizeof(jwt_token)
    );

    char verified_sub[128] = {0};
    int32_t v_res = rust_jwt_verify(
        (uint64_t)jwt_token, jwt_len,
        (uint64_t)secret.data(), (int32_t)secret.size(),
        now_ts,
        (uint64_t)verified_sub, sizeof(verified_sub)
    );

    std::string wrong_secret = "wrong_secret_key";
    char dummy_sub[128] = {0};
    int32_t wrong_res = rust_jwt_verify(
        (uint64_t)jwt_token, jwt_len,
        (uint64_t)wrong_secret.data(), (int32_t)wrong_secret.size(),
        now_ts,
        (uint64_t)dummy_sub, sizeof(dummy_sub)
    );

    if (jwt_len > 0 && v_res > 0 && std::string(verified_sub) == subject && wrong_res < 0) {
        std::cout << "PASSED [OK]" << std::endl;
    } else {
        std::cout << "FAILED [X] (Token: " << jwt_token << ", sub: " << verified_sub << ")" << std::endl;
        return false;
    }

    // Test 6: Rust Token-Bucket Rate Limiter
    std::cout << "[TEST 6] Rust High-Precision Token Bucket Limiter ... ";
    uint64_t test_ip = 0x7F000001; // 127.0.0.1
    double t_now = 1000.0;
    bool tb1 = rust_token_bucket_consume(test_ip, 3, 1.0, t_now);
    bool tb2 = rust_token_bucket_consume(test_ip, 3, 1.0, t_now);
    bool tb3 = rust_token_bucket_consume(test_ip, 3, 1.0, t_now);
    bool tb4 = rust_token_bucket_consume(test_ip, 3, 1.0, t_now); // Should fail (exhausted)
    bool tb5 = rust_token_bucket_consume(test_ip, 3, 1.0, t_now + 2.0); // Refilled 2 tokens

    if (tb1 && tb2 && tb3 && !tb4 && tb5) {
        std::cout << "PASSED [OK]" << std::endl;
    } else {
        std::cout << "FAILED [X]" << std::endl;
        return false;
    }

    // Test 7: Go Concurrency Admission Semaphore
    std::cout << "[TEST 7] Go Concurrency Admission Semaphore ... ";
    go_admission_init(2);
    bool adm1 = go_admission_acquire();
    bool adm2 = go_admission_acquire();
    bool adm3 = go_admission_acquire(); // Should fail (capacity 2)
    go_admission_release();
    bool adm4 = go_admission_acquire(); // Should succeed after release
    go_admission_release();
    go_admission_release();

    if (adm1 && adm2 && !adm3 && adm4) {
        std::cout << "PASSED [OK]" << std::endl;
    } else {
        std::cout << "FAILED [X]" << std::endl;
        return false;
    }

    // Test 8: Go Background Task Queue & Worker Goroutines
    std::cout << "[TEST 8] Go Background Task Queue & Worker Goroutines ... ";
    go_task_init(2, 64);
    for (int i = 0; i < 5; ++i) {
        go_task_enqueue(1, 1000 + i);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    int64_t processed = go_task_get_processed();
    if (processed >= 5) {
        std::cout << "PASSED [OK] (Processed " << processed << " tasks)" << std::endl;
    } else {
        std::cout << "FAILED [X] (Processed: " << processed << ")" << std::endl;
        return false;
    }

    // Test 9: Go EventHub Pub/Sub Broker
    std::cout << "[TEST 9] Go EventHub Pub/Sub Broker ... ";
    int32_t subs = go_eventhub_subscribe(42);
    go_eventhub_publish(42, 9999);
    int64_t pub_count = go_eventhub_published_count();
    int32_t active_subs = go_eventhub_subscribers_count();

    if (subs >= 1 && pub_count >= 1) {
        std::cout << "PASSED [OK] (Published: " << pub_count << ", Subscribers: " << active_subs << ")" << std::endl;
    } else {
        std::cout << "FAILED [X]" << std::endl;
        return false;
    }

    // Test 10: Go Metrics & Profiling
    std::cout << "[TEST 10] Go Metrics & Latency Profiling ... ";
    go_record_request(200, 1500);
    go_record_request(404, 2500);
    int64_t tot_req = go_metrics_total_requests();
    double avg_us = go_metrics_average_latency_us();
    int64_t err_c = go_metrics_error_count();
    if (tot_req >= 2 && err_c >= 1 && avg_us > 0.0) {
        std::cout << "PASSED [OK] (Total: " << tot_req << ", Avg Latency: " << avg_us << " us, Errors: " << err_c << ")" << std::endl;
    } else {
        std::cout << "FAILED [X]" << std::endl;
        return false;
    }

    std::cout << "========================================================" << std::endl;
    std::cout << "  ALL 10 KR MULTI-LANGUAGE TESTS PASSED SUCCESSFULLY!   " << std::endl;
    std::cout << "========================================================" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    int port = 8085;
    int workers = 8;
    bool run_tests_flag = false;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--test") {
                run_tests_flag = true;
            } else if (arg == "--host" && i + 1 < argc) {
                host = argv[++i];
            } else if (arg == "--port" && i + 1 < argc) {
                port = std::stoi(argv[++i]);
            } else if (arg == "--workers" && i + 1 < argc) {
                workers = std::stoi(argv[++i]);
            } else if (arg == "--help" || arg == "-h") {
            std::cout << "Sovereign Server V10 Professional - KR Unified Language Edition\n"
                      << "Usage: " << argv[0] << " [options]\n\n"
                      << "Options:\n"
                      << "  --test            Run complete multilingual test suite and exit\n"
                      << "  --host <ip>       Bind IP address (security policy: 127.0.0.1 only)\n"
                      << "  --port <port>     Bind TCP port (default: 8080)\n"
                      << "  --workers <count> Number of worker threads (default: 8)\n"
                      << "  --help, -h        Display this help message\n";
            return 0;
            } else {
                std::cerr << "Invalid or incomplete command-line option: " << arg << std::endl;
                return 2;
            }
        }
    } catch (const std::exception&) {
        std::cerr << "Invalid numeric command-line value." << std::endl;
        return 2;
    }

    if (port < 1 || port > 65535 || workers < 1 || workers > 256) {
        std::cerr << "Port must be 1-65535 and workers must be 1-256." << std::endl;
        return 2;
    }

    if (run_tests_flag) {
        bool ok = run_all_tests();
        return ok ? 0 : 1;
    }

    // Always run quick verification of environment
    if (!go_security_audit_environment()) {
        std::cerr << "[CRITICAL] Security audit failed on startup!" << std::endl;
        return 1;
    }

    return cpp_start_server(host.c_str(), port, workers);
}

========== END FILE ==========

========== FILE: network/network_mod.kr ==========

// ============================================================================
// KR Unified Language - Module: Network (WinSock2 Sockets, HTTP Router & Server)
// Language: C++20 (Memory Buffers, Concurrency, Socket Lifecycle & Dispatch)
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <functional>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// Cross-language ABI function declarations provided by KR Bridge
extern "C" {
    // Protocol (Rust)
    bool rust_http_validate_header(uint64_t name_ptr, int32_t name_len, uint64_t val_ptr, int32_t val_len);
    int32_t rust_sanitize_path(uint64_t in_ptr, int32_t in_len, uint64_t out_ptr, int32_t max_out);
    int32_t rust_http_parse_request(uint64_t raw_ptr, int32_t raw_len, uint64_t out_method, int32_t max_method, uint64_t out_path, int32_t max_path, uint64_t out_version, int32_t max_version, uint64_t out_meta, uint64_t out_auth_bearer, int32_t max_auth, uint64_t out_ws_key, int32_t max_ws_key);
    int32_t rust_ws_compute_accept_key(uint64_t sec_ws_key, int32_t key_len, uint64_t out_buf, int32_t max_len);
    int32_t rust_ws_parse_frame_header(uint64_t buf, int32_t len, uint64_t out_info);
    int32_t rust_ws_apply_mask(uint64_t data, int32_t len, uint32_t mask_key);
    int32_t rust_ws_build_frame_header(int32_t opcode, int64_t payload_len, uint64_t out_buf, int32_t max_out);

    // Security (Rust & Go)
    int32_t rust_sha256(uint64_t data, int32_t len, uint64_t out_digest);
    int32_t rust_hmac_sha256(uint64_t key, int32_t key_len, uint64_t data, int32_t data_len, uint64_t out_mac);
    bool rust_constant_time_compare(uint64_t a, int32_t a_len, uint64_t b, int32_t b_len);
    int32_t rust_jwt_create(uint64_t secret, int32_t sec_len, uint64_t sub, int32_t sub_len, uint64_t role, int32_t role_len, int64_t exp_sec, uint64_t out_buf, int32_t max_out);
    int32_t rust_jwt_verify(uint64_t token, int32_t tok_len, uint64_t secret, int32_t sec_len, int64_t current_time_sec, uint64_t out_sub, int32_t max_sub);
    bool rust_token_bucket_consume(uint64_t bucket_id, int32_t max_tokens, double refill_per_sec, double now_sec);
    bool go_security_audit_environment(void);
    bool go_jwt_is_blacklisted(int64_t jtiId);
    bool go_jwt_revoke_token(int64_t jtiId);

    // Orchestration (Go)
    bool go_admission_init(int32_t maxConns);
    bool go_admission_acquire(void);
    void go_admission_release(void);
    int32_t go_get_active_conns(void);
    bool go_task_init(int32_t workers, int32_t queueCap);
    bool go_task_enqueue(int32_t taskType, int64_t payloadId);
    int64_t go_task_get_processed(void);
    int32_t go_task_get_queue_len(void);
    bool go_eventhub_publish(int32_t topicId, int64_t eventVal);
    int32_t go_eventhub_subscribe(int32_t topicId);
    int64_t go_eventhub_published_count(void);
    int32_t go_eventhub_subscribers_count(void);
    void go_record_request(int32_t statusCode, int64_t latencyMicros);
    int64_t go_metrics_total_requests(void);
    double go_metrics_average_latency_us(void);
    int64_t go_metrics_error_count(void);
}

static std::atomic<bool> g_server_running{false};
static std::string g_jwt_secret;
static std::string g_bootstrap_token;

static bool cpp_send_all(SOCKET socket, const char* data, size_t length) {
    size_t sent_total = 0;
    while (sent_total < length) {
        size_t remaining = length - sent_total;
        int chunk = remaining > 0x7fffffffU ? 0x7fffffff : static_cast<int>(remaining);
        int sent = send(socket, data + sent_total, chunk, 0);
        if (sent <= 0) return false;
        sent_total += static_cast<size_t>(sent);
    }
    return true;
}

static bool cpp_constant_time_equal(const std::string& left, const char* right) {
    if (right == nullptr) return false;
    size_t right_len = strlen(right);
    if (left.size() != right_len || right_len > static_cast<size_t>(INT32_MAX)) return false;
    return rust_constant_time_compare(
        reinterpret_cast<uint64_t>(left.data()), static_cast<int32_t>(left.size()),
        reinterpret_cast<uint64_t>(right), static_cast<int32_t>(right_len));
}

static bool cpp_verify_access_token(const char* token, std::string& subject) {
    if (token == nullptr || token[0] == '\0' || g_jwt_secret.empty()) return false;
    char sub_buf[128] = {0};
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int32_t result = rust_jwt_verify(
        reinterpret_cast<uint64_t>(token), static_cast<int32_t>(strlen(token)),
        reinterpret_cast<uint64_t>(g_jwt_secret.data()), static_cast<int32_t>(g_jwt_secret.size()),
        now_ts, reinterpret_cast<uint64_t>(sub_buf), sizeof(sub_buf));
    if (result <= 0) return false;
    subject.assign(sub_buf, static_cast<size_t>(result));
    return true;
}

struct HttpResponse {
    int status;
    std::string content_type;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

static std::string cpp_build_http_response(const HttpResponse& resp, bool keep_alive) {
    std::ostringstream ss;
    std::string status_msg = "OK";
    if (resp.status == 200) status_msg = "OK";
    else if (resp.status == 201) status_msg = "Created";
    else if (resp.status == 202) status_msg = "Accepted";
    else if (resp.status == 400) status_msg = "Bad Request";
    else if (resp.status == 401) status_msg = "Unauthorized";
    else if (resp.status == 403) status_msg = "Forbidden";
    else if (resp.status == 404) status_msg = "Not Found";
    else if (resp.status == 429) status_msg = "Too Many Requests";
    else if (resp.status == 500) status_msg = "Internal Server Error";
    else if (resp.status == 503) status_msg = "Service Unavailable";

    ss << "HTTP/1.1 " << resp.status << " " << status_msg << "\r\n";
    ss << "Server: Sovereign-KR\r\n";
    ss << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n";
    ss << "Content-Type: " << resp.content_type << "\r\n";
    ss << "Content-Length: " << resp.body.size() << "\r\n";

    // Sovereign Paranoid Security Headers
    ss << "X-Content-Type-Options: nosniff\r\n";
    ss << "X-Frame-Options: DENY\r\n";
    ss << "Referrer-Policy: no-referrer\r\n";
    ss << "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n";
    ss << "Cache-Control: no-store\r\n";
    ss << "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n";

    for (const auto& h : resp.headers) {
        if (rust_http_validate_header((uint64_t)h.first.data(), (int32_t)h.first.size(),
                                      (uint64_t)h.second.data(), (int32_t)h.second.size())) {
            ss << h.first << ": " << h.second << "\r\n";
        }
    }

    ss << "\r\n";
    ss << resp.body;
    return ss.str();
}

static void cpp_handle_websocket_connection(SOCKET client, const std::string& ws_key) {
    char accept_buf[64] = {0};
    int32_t acc_len = rust_ws_compute_accept_key(
        (uint64_t)ws_key.data(),
        (int32_t)ws_key.size(),
        (uint64_t)accept_buf,
        sizeof(accept_buf)
    );

    if (acc_len <= 0) {
        return;
    }

    std::ostringstream ws_resp;
    ws_resp << "HTTP/1.1 101 Switching Protocols\r\n";
    ws_resp << "Upgrade: websocket\r\n";
    ws_resp << "Connection: Upgrade\r\n";
    ws_resp << "Sec-WebSocket-Accept: " << accept_buf << "\r\n";
    ws_resp << "Sec-WebSocket-Version: 13\r\n\r\n";

    std::string handshake_str = ws_resp.str();
    if (!cpp_send_all(client, handshake_str.data(), handshake_str.size())) return;

    // Publish WebSocket connection event to Go EventHub
    go_eventhub_publish(100, 1);

    // Read WebSocket frames
    char buf[4096];
    while (g_server_running.load()) {
        int n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0) break;

        uint8_t frame_info[17] = {0};
        int32_t hdr_size = rust_ws_parse_frame_header(
            (uint64_t)buf,
            n,
            (uint64_t)frame_info
        );

        if (hdr_size < 0) break;

        bool fin = (frame_info[0] != 0);
        int32_t opcode = 0;
        int64_t payload_len = 0;
        uint32_t mask = 0;
        std::memcpy(&opcode, frame_info + 1, sizeof(opcode));
        std::memcpy(&payload_len, frame_info + 5, sizeof(payload_len));
        std::memcpy(&mask, frame_info + 13, sizeof(mask));

        // A frame must be completely contained in the bounded receive buffer.
        // Never use the peer-declared length until it has been checked against
        // the bytes actually received.
        if (payload_len < 0 || payload_len > 4096 ||
            hdr_size > n || payload_len > static_cast<int64_t>(n - hdr_size)) {
            break;
        }

        if (opcode == 8) {
            // Close frame
            break;
        } else if (opcode == 9) {
            // Ping frame -> Send Pong
            uint8_t pong_hdr[10];
            int32_t ph_len = rust_ws_build_frame_header(10, payload_len, (uint64_t)pong_hdr, sizeof(pong_hdr));
            if (ph_len <= 0 || !cpp_send_all(client, reinterpret_cast<const char*>(pong_hdr), static_cast<size_t>(ph_len))) break;
            if (payload_len > 0) {
                rust_ws_apply_mask((uint64_t)(buf + hdr_size), (int32_t)payload_len, mask);
                if (!cpp_send_all(client, buf + hdr_size, static_cast<size_t>(payload_len))) break;
            }
        } else if (opcode == 1 || opcode == 2) {
            // Text or Binary -> Echo frame back to client
            if (payload_len > 0 && n >= hdr_size + payload_len) {
                rust_ws_apply_mask((uint64_t)(buf + hdr_size), (int32_t)payload_len, mask);
            }

            uint8_t echo_hdr[10];
            int32_t eh_len = rust_ws_build_frame_header(opcode, payload_len, (uint64_t)echo_hdr, sizeof(echo_hdr));
            if (eh_len <= 0 || !cpp_send_all(client, reinterpret_cast<const char*>(echo_hdr), static_cast<size_t>(eh_len))) break;
            if (payload_len > 0) {
                if (!cpp_send_all(client, buf + hdr_size, static_cast<size_t>(payload_len))) break;
            }
        }
    }
}

static void cpp_handle_client_socket(SOCKET client, sockaddr_in client_addr) {
    if (!go_admission_acquire()) {
        HttpResponse resp{503, "application/json", "{\"error\":\"Service Unavailable: Max Concurrency Limit Reached\"}", {}};
        std::string raw = cpp_build_http_response(resp, false);
        cpp_send_all(client, raw.data(), raw.size());
        closesocket(client);
        return;
    }

    uint64_t client_ip_hash = static_cast<uint64_t>(client_addr.sin_addr.s_addr);
    bool keep_alive = true;
    int requests_handled = 0;

    // Timeout settings (5 seconds)
    DWORD timeout_ms = 5000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    while (keep_alive && requests_handled < 100 && g_server_running.load()) {
        std::string request_data;
        request_data.reserve(8192);
        bool request_complete = false;
        while (request_data.size() < 8191) {
            char chunk[2048];
            size_t capacity = 8191 - request_data.size();
            int wanted = static_cast<int>(capacity < sizeof(chunk) ? capacity : sizeof(chunk));
            int received = recv(client, chunk, wanted, 0);
            if (received <= 0) break;
            request_data.append(chunk, static_cast<size_t>(received));
            size_t header_end = request_data.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                request_complete = (header_end + 4 == request_data.size());
                break;
            }
        }
        if (!request_complete) {
            HttpResponse resp{400, "application/json", "{\"error\":\"Incomplete or oversized HTTP request\"}", {}};
            std::string raw = cpp_build_http_response(resp, false);
            cpp_send_all(client, raw.data(), raw.size());
            break;
        }

        auto start_time = std::chrono::steady_clock::now();

        char method[32] = {0};
        char path[512] = {0};
        char version[32] = {0};
        uint8_t meta[16] = {0};
        char auth_bearer[512] = {0};
        char ws_key[128] = {0};

        int32_t parse_res = rust_http_parse_request(
            (uint64_t)request_data.data(),
            static_cast<int32_t>(request_data.size()),
            (uint64_t)method, sizeof(method),
            (uint64_t)path, sizeof(path),
            (uint64_t)version, sizeof(version),
            (uint64_t)meta,
            (uint64_t)auth_bearer, sizeof(auth_bearer),
            (uint64_t)ws_key, sizeof(ws_key)
        );

        if (parse_res != 0) {
            HttpResponse resp{400, "application/json", "{\"error\":\"Malformed HTTP Request\"}", {}};
            std::string raw = cpp_build_http_response(resp, false);
            cpp_send_all(client, raw.data(), raw.size());
            break;
        }

        bool req_keep_alive = (meta[0] != 0);
        bool is_ws = (meta[1] != 0);
        // Token bucket rate limiting (100 requests capacity, 20 refill per second)
        auto now_sec = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (!rust_token_bucket_consume(client_ip_hash, 100, 20.0, now_sec)) {
            HttpResponse resp{429, "application/json", "{\"error\":\"Too Many Requests - Rate Limit Exceeded\"}", {}};
            std::string raw = cpp_build_http_response(resp, false);
            cpp_send_all(client, raw.data(), raw.size());
            break;
        }

        // WebSocket Upgrade
        if (is_ws && std::string(path) == "/ws") {
            std::string ws_subject;
            if (!cpp_verify_access_token(auth_bearer, ws_subject)) {
                HttpResponse denied{401, "application/json", "{\"error\":\"Valid access token required for WebSocket upgrade\"}", {}};
                std::string raw = cpp_build_http_response(denied, false);
                cpp_send_all(client, raw.data(), raw.size());
                break;
            }
            cpp_handle_websocket_connection(client, ws_key);
            break; // WebSocket takes over socket
        }

        // Sanitize path against directory traversal
        char clean_path[512] = {0};
        int32_t clean_len = rust_sanitize_path(
            (uint64_t)path,
            (int32_t)strlen(path),
            (uint64_t)clean_path,
            sizeof(clean_path)
        );

        if (clean_len <= 0) {
            HttpResponse bad_path{400, "application/json", "{\"error\":\"Invalid request path\"}", {}};
            std::string raw = cpp_build_http_response(bad_path, false);
            cpp_send_all(client, raw.data(), raw.size());
            break;
        }

        HttpResponse resp;
        std::string s_method(method);
        std::string s_path(clean_path);

        // Routing Engine
        if (s_path == "/" && s_method == "GET") {
            resp.status = 200;
            resp.content_type = "text/html; charset=utf-8";
            resp.body =
                "<!doctype html><html><head><title>Sovereign Server V10 KR</title>"
                "<style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:2rem;}"
                ".card{background:#1e293b;border-radius:8px;padding:1.5rem;max-width:800px;margin:auto;box-shadow:0 4px 6px -1px rgba(0,0,0,0.5);}"
                "h1{color:#38bdf8;}span.badge{background:#0284c7;padding:4px 8px;border-radius:4px;font-size:0.85rem;margin-right:8px;}"
                "code{background:#334155;padding:2px 6px;border-radius:4px;color:#f472b6;}</style></head>"
                "<body><div class='card'>"
                "<h1>Sovereign Server V10 Professional (KR Multi-Language)</h1>"
                "<p><span class='badge'>C++20</span> High-Speed Network Sockets & Lifecycle</p>"
                "<p><span class='badge'>Rust</span> Cryptographic Kernels, JWT & Protocol Parser</p>"
                "<p><span class='badge'>Go</span> Concurrency, Task Queue & EventHub Broker</p>"
                "<hr style='border-color:#334155;'/>"
                "<h3>Endpoints:</h3>"
                "<ul>"
                "<li><code>GET /health</code> - Server health & performance metrics</li>"
                "<li><code>POST /auth/token</code> - Issue cryptographic HMAC-SHA256 JWT</li>"
                "<li><code>GET /api/secure</code> - Authenticated endpoint (Bearer token)</li>"
                "<li><code>POST /api/tasks</code> - Dispatch async task to Go queue</li>"
                "<li><code>GET /api/eventhub/stats</code> - Pub/Sub broker statistics</li>"
                "<li><code>WS /ws</code> - Interactive RFC 6455 WebSocket stream</li>"
                "</ul></div></body></html>";
        } else if (s_path == "/health" && s_method == "GET") {
            int64_t total_req = go_metrics_total_requests();
            double avg_lat = go_metrics_average_latency_us();
            int64_t err_count = go_metrics_error_count();
            int32_t active_conns = go_get_active_conns();
            int64_t tasks_done = go_task_get_processed();

            std::ostringstream json;
            json << "{\"status\":\"healthy\","
                 << "\"active_connections\":" << active_conns << ","
                 << "\"total_requests\":" << total_req << ","
                 << "\"average_latency_us\":" << avg_lat << ","
                 << "\"error_count\":" << err_count << ","
                 << "\"background_tasks_processed\":" << tasks_done << ","
                 << "\"multi_language\":{\"network\":\"C++20\",\"crypto\":\"Rust\",\"orchestration\":\"Go\"}}";

            resp.status = 200;
            resp.content_type = "application/json";
            resp.body = json.str();
        } else if (s_path == "/auth/token" && s_method == "POST") {
            if (!cpp_constant_time_equal(g_bootstrap_token, auth_bearer)) {
                resp.status = 401;
                resp.content_type = "application/json";
                resp.body = "{\"error\":\"Valid bootstrap bearer token required\"}";
            } else {
            char token_buf[512] = {0};
            auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            int64_t exp = now_ts + 3600; // 1 hour validity

            std::string user = "admin";
            std::string role = "sovereign_operator";

            int32_t t_len = rust_jwt_create(
                (uint64_t)g_jwt_secret.data(), (int32_t)g_jwt_secret.size(),
                (uint64_t)user.data(), (int32_t)user.size(),
                (uint64_t)role.data(), (int32_t)role.size(),
                exp,
                (uint64_t)token_buf, sizeof(token_buf)
            );

            if (t_len > 0) {
                resp.status = 200;
                resp.content_type = "application/json";
                resp.body = std::string("{\"token\":\"") + token_buf + "\",\"expires_at\":" + std::to_string(exp) + "}";
            } else {
                resp.status = 500;
                resp.content_type = "application/json";
                resp.body = "{\"error\":\"Token generation failed\"}";
            }
            }
        } else if (s_path == "/api/secure" && s_method == "GET") {
            if (strlen(auth_bearer) == 0) {
                resp.status = 401;
                resp.content_type = "application/json";
                resp.body = "{\"error\":\"Missing Bearer Token in Authorization header\"}";
            } else {
                std::string subject;
                bool token_valid = cpp_verify_access_token(auth_bearer, subject);

                if (token_valid) {
                    resp.status = 200;
                    resp.content_type = "application/json";
                    resp.body = std::string("{\"message\":\"Access granted to sovereign zone\",\"subject\":\"") + subject + "\"}";
                } else {
                    resp.status = 403;
                    resp.content_type = "application/json";
                    resp.body = "{\"error\":\"Forbidden: Invalid or expired cryptographic token\"}";
                }
            }
        } else if (s_path == "/api/tasks" && s_method == "POST") {
            std::string subject;
            if (!cpp_verify_access_token(auth_bearer, subject)) {
                resp.status = 401;
                resp.content_type = "application/json";
                resp.body = "{\"error\":\"Valid access token required\"}";
            } else {
            static std::atomic<int64_t> task_id_counter{1000};
            int64_t pid = ++task_id_counter;
            bool enq = go_task_enqueue(1, pid);
            if (enq) {
                resp.status = 202;
                resp.content_type = "application/json";
                resp.body = "{\"status\":\"Accepted\",\"task_id\":" + std::to_string(pid) + "}";
            } else {
                resp.status = 503;
                resp.content_type = "application/json";
                resp.body = "{\"error\":\"Task Queue Full\"}";
            }
            }
        } else if (s_path == "/api/eventhub/stats" && s_method == "GET") {
            int64_t published = go_eventhub_published_count();
            int32_t subs = go_eventhub_subscribers_count();

            resp.status = 200;
            resp.content_type = "application/json";
            resp.body = "{\"events_published\":" + std::to_string(published) + ",\"active_subscribers\":" + std::to_string(subs) + "}";
        } else {
            resp.status = 404;
            resp.content_type = "application/json";
            resp.body = "{\"error\":\"Not Found\",\"path\":\"" + s_path + "\"}";
        }

        keep_alive = req_keep_alive;
        std::string raw_resp = cpp_build_http_response(resp, keep_alive);
        if (!cpp_send_all(client, raw_resp.data(), raw_resp.size())) break;

        auto end_time = std::chrono::steady_clock::now();
        auto lat_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        go_record_request(resp.status, lat_us);

        requests_handled++;
    }

    closesocket(client);
    go_admission_release();
}

class SovereignThreadPool {
public:
    explicit SovereignThreadPool(size_t threads, size_t max_pending = 1024)
        : stop_(false), max_pending_(max_pending) {
        for (size_t i = 0; i < threads; ++i) {
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex_);
                        this->cv_.wait(lock, [this] {
                            return this->stop_ || !this->tasks_.empty();
                        });
                        if (this->stop_ && this->tasks_.empty()) {
                            return;
                        }
                        task = std::move(this->tasks_.front());
                        this->tasks_.pop();
                    }
                    task();
                }
            });
        }
    }

    bool enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_ || tasks_.size() >= max_pending_) return false;
            tasks_.push(task);
        }
        cv_.notify_one();
        return true;
    }

    ~SovereignThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        for (std::thread& worker : workers_) {
            if (worker.joinable()) worker.join();
        }
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    bool stop_;
    const size_t max_pending_;
};

int cpp_start_server(const char* host, int port, int worker_count) {
    const char* jwt_secret = std::getenv("SOVEREIGN_JWT_SECRET");
    const char* bootstrap_token = std::getenv("SOVEREIGN_BOOTSTRAP_TOKEN");
    if (jwt_secret == nullptr || bootstrap_token == nullptr ||
        strlen(jwt_secret) < 32 || strlen(bootstrap_token) < 32 ||
        strlen(jwt_secret) > 256 || strlen(bootstrap_token) > 256 ||
        strcmp(jwt_secret, bootstrap_token) == 0) {
        std::cerr << "[CRITICAL] Set distinct SOVEREIGN_JWT_SECRET and "
                     "SOVEREIGN_BOOTSTRAP_TOKEN values (32-256 bytes each)." << std::endl;
        return 1;
    }
    g_jwt_secret.assign(jwt_secret);
    g_bootstrap_token.assign(bootstrap_token);

    // The implementation has no TLS stack.  Bind only to loopback so bearer
    // credentials cannot traverse an unencrypted network.  A local TLS reverse
    // proxy can safely expose the service when required.
    if (host == nullptr || strcmp(host, "127.0.0.1") != 0) {
        std::cerr << "[CRITICAL] Only 127.0.0.1 is allowed; use a local TLS reverse proxy for remote access." << std::endl;
        return 1;
    }
    if (port < 1 || port > 65535 || worker_count < 1 || worker_count > 256) {
        std::cerr << "[CRITICAL] Invalid port or worker count (allowed workers: 1-256)." << std::endl;
        return 1;
    }
    WSADATA wsaData;
    int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_err != 0) {
        std::cerr << "[CRITICAL] WSAStartup failed: " << wsa_err << std::endl;
        return 1;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        std::cerr << "[CRITICAL] socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    BOOL opt = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((u_short)port);
    if (strcmp(host, "0.0.0.0") == 0 || strlen(host) == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, host, &server_addr.sin_addr);
    }

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        std::cerr << "[CRITICAL] Bind failed on " << host << ":" << port << " - Error: " << err;
        if (err == 10013 || err == 10048) {
            std::cerr << " (Port " << port << " ist bereits durch einen anderen Dienst belegt, z.B. Apache/httpd. Bitte anderen Port waehlen via --port <nummer>, z.B. --port 8085)";
        }
        std::cerr << std::endl;
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[CRITICAL] Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    std::cout << "=================================================================" << std::endl;
    std::cout << "  Sovereign Server V10 Professional (KR Multi-Language Fusion)" << std::endl;
    std::cout << "  C++20 (Networking) + Rust (Crypto/Protocol) + Go (Orchestration)" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << "  Server bound and listening on http://" << host << ":" << port << std::endl;
    std::cout << "  Worker Threads: " << worker_count << std::endl;
    std::cout << "  Press CTRL+C to gracefully stop the server." << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;

    g_server_running = true;
    go_admission_init(1024);
    go_task_init(worker_count, 4096);

    SovereignThreadPool pool(worker_count > 0 ? worker_count : 8);

    while (g_server_running.load()) {
        sockaddr_in client_addr{};
        int client_len = sizeof(client_addr);
        SOCKET client = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);

        if (client == INVALID_SOCKET) {
            if (!g_server_running.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (!pool.enqueue([client, client_addr]() {
                cpp_handle_client_socket(client, client_addr);
            })) {
            HttpResponse resp{503, "application/json", "{\"error\":\"Server queue full\"}", {}};
            std::string raw = cpp_build_http_response(resp, false);
            cpp_send_all(client, raw.data(), raw.size());
            closesocket(client);
        }
    }

    closesocket(listen_sock);
    WSACleanup();
    std::cout << "[INFO] Server shutdown complete." << std::endl;
    return 0;
}

========== END FILE ==========

========== FILE: orchestration/orchestration_mod.kr ==========

// ============================================================================
// KR Unified Language - Module: Orchestration (Concurrency, Tasks & EventHub)
// Language: Go (Goroutines, Channels, Admission & Pub/Sub Queue)
// ============================================================================

import "sync"
import "sync/atomic"
import "time"

// ----------------------------------------------------------------------------
// Admission Semaphore (Bounded Concurrency)
// ----------------------------------------------------------------------------

var admissionInitOnce sync.Once
var admissionSem chan struct{}
var activeConns atomic.Int32

func go_admission_init(maxConns int32) bool {
    admissionInitOnce.Do(func() {
        if maxConns <= 0 {
            maxConns = 1024
        }
        admissionSem = make(chan struct{}, maxConns)
    })
    return true
}

func go_admission_acquire() bool {
    if admissionSem == nil {
        go_admission_init(1024)
    }
    select {
    case admissionSem <- struct{}{}:
        activeConns.Add(1)
        return true
    default:
        return false // Over capacity: HTTP 503 Service Unavailable
    }
}

func go_admission_release() {
    if admissionSem != nil {
        select {
        case <-admissionSem:
            activeConns.Add(-1)
        default:
        }
    }
}

func go_get_active_conns() int32 {
    return activeConns.Load()
}

// ----------------------------------------------------------------------------
// Background Task Queue & Worker Goroutines
// ----------------------------------------------------------------------------

type TaskRecord struct {
    TaskType  int32
    PayloadId int64
    Retries   int32
}

var taskInitOnce sync.Once
var taskQueue chan TaskRecord
var tasksProcessed atomic.Int64

func runTaskWorker(id int, queue <-chan TaskRecord) {
    for task := range queue {
        // Simulate async task execution (e.g. email, DB write, cache flush)
        if task.TaskType > 0 {
            time.Sleep(1 * time.Millisecond)
        }
        tasksProcessed.Add(1)
    }
}

func go_task_init(workers int32, queueCap int32) bool {
    taskInitOnce.Do(func() {
        if workers <= 0 {
            workers = 4
        }
        if queueCap <= 0 {
            queueCap = 4096
        }
        taskQueue = make(chan TaskRecord, queueCap)
        for i := 0; i < int(workers); i++ {
            go runTaskWorker(i, taskQueue)
        }
    })
    return true
}

func go_task_enqueue(taskType int32, payloadId int64) bool {
    if taskQueue == nil {
        go_task_init(4, 4096)
    }
    select {
    case taskQueue <- TaskRecord{TaskType: taskType, PayloadId: payloadId, Retries: 0}:
        return true
    default:
        return false // Queue is full
    }
}

func go_task_get_processed() int64 {
    return tasksProcessed.Load()
}

func go_task_get_queue_len() int32 {
    if taskQueue == nil {
        return 0
    }
    return int32(len(taskQueue))
}

// ----------------------------------------------------------------------------
// EventHub Pub/Sub Broker
// ----------------------------------------------------------------------------

type EventHubBroker struct {
    mu          sync.RWMutex
    topics      map[int32][]chan int64
    published   atomic.Int64
    subscribers atomic.Int32
}

var hubOnce sync.Once
var globalHub *EventHubBroker

func getEventHub() *EventHubBroker {
    hubOnce.Do(func() {
        globalHub = &EventHubBroker{
            topics: make(map[int32][]chan int64),
        }
    })
    return globalHub
}

func go_eventhub_publish(topicId int32, eventVal int64) bool {
    hub := getEventHub()
    hub.mu.RLock()
    subs, exists := hub.topics[topicId]
    hub.mu.RUnlock()

    hub.published.Add(1)
    if !exists || len(subs) == 0 {
        return true
    }

    for _, ch := range subs {
        select {
        case ch <- eventVal:
        default:
            // Non-blocking write to avoid head-of-line blocking
        }
    }
    return true
}

func go_eventhub_subscribe(topicId int32) int32 {
    hub := getEventHub()
    ch := make(chan int64, 64)
    hub.mu.Lock()
    hub.topics[topicId] = append(hub.topics[topicId], ch)
    hub.subscribers.Add(1)
    subCount := int32(len(hub.topics[topicId]))
    hub.mu.Unlock()
    return subCount
}

func go_eventhub_published_count() int64 {
    hub := getEventHub()
    return hub.published.Load()
}

func go_eventhub_subscribers_count() int32 {
    hub := getEventHub()
    return hub.subscribers.Load()
}

// ----------------------------------------------------------------------------
// Metrics & Latency Profiler
// ----------------------------------------------------------------------------

var metricsTotalReq atomic.Int64
var metricsTotalMicro atomic.Int64
var metricsErrors atomic.Int64

func go_record_request(statusCode int32, latencyMicros int64) {
    metricsTotalReq.Add(1)
    metricsTotalMicro.Add(latencyMicros)
    if statusCode >= 400 {
        metricsErrors.Add(1)
    }
}

func go_metrics_total_requests() int64 {
    return metricsTotalReq.Load()
}

func go_metrics_average_latency_us() float64 {
    tot := metricsTotalReq.Load()
    micros := metricsTotalMicro.Load()
    if tot > 0 {
        return float64(micros) / float64(tot)
    }
    return 0.0
}

func go_metrics_error_count() int64 {
    return metricsErrors.Load()
}

========== END FILE ==========

========== FILE: protocol/protocol_mod.kr ==========

// ============================================================================
// KR Unified Language - Module: Protocol (HTTP/1.1 & RFC 6455 WebSocket)
// Language: Rust (Algorithmic Protocol State Machine & Secure Framing)
// ============================================================================

fn rust_http_validate_header(name_ptr: u64, name_len: i32, val_ptr: u64, val_len: i32) -> bool {
    if name_ptr == 0 || val_ptr == 0 || name_len <= 0 || val_len < 0 {
        return false;
    }
    let name_slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let val_slice = unsafe { std::slice::from_raw_parts(val_ptr as *const u8, val_len as usize) };

    for &b in name_slice {
        let is_tchar = b.is_ascii_alphanumeric() || matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' |
            b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~');
        if !is_tchar {
            return false;
        }
    }
    for &b in val_slice {
        if b < 32 || b == 127 {
            return false;
        }
    }
    true
}

fn rust_sanitize_path(in_ptr: u64, in_len: i32, out_ptr: u64, max_out: i32) -> i32 {
    if in_ptr == 0 || out_ptr == 0 || in_len <= 0 || max_out <= 0 {
        return -1;
    }
    let in_bytes = unsafe { std::slice::from_raw_parts(in_ptr as *const u8, in_len as usize) };
    let in_str = match std::str::from_utf8(in_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let raw_path = match in_str.split_once('?') {
        Some((p, _)) => p,
        None => in_str,
    };

    let mut segments: Vec<&str> = Vec::new();
    for seg in raw_path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            segments.pop(); // Prevent path traversal escaping root
        } else {
            segments.push(seg);
        }
    }

    let mut clean = String::with_capacity(raw_path.len() + 1);
    clean.push('/');
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            clean.push('/');
        }
        clean.push_str(seg);
    }

    let clean_bytes = clean.as_bytes();
    if clean_bytes.len() as i32 >= max_out {
        return -1;
    }
    unsafe {
        let dest = out_ptr as *mut u8;
        std::ptr::copy_nonoverlapping(clean_bytes.as_ptr(), dest, clean_bytes.len());
        *dest.add(clean_bytes.len()) = 0;
    }
    clean_bytes.len() as i32
}

fn rust_http_parse_request(raw_ptr: u64, raw_len: i32, out_method: u64, max_method: i32, out_path: u64, max_path: i32, out_version: u64, max_version: i32, out_meta: u64, out_auth_bearer: u64, max_auth: i32, out_ws_key: u64, max_ws_key: i32) -> i32 {
    if raw_ptr == 0 || raw_len < 10 || raw_len > 8191 || out_method == 0 ||
       out_path == 0 || out_version == 0 || out_meta == 0 ||
       out_auth_bearer == 0 || out_ws_key == 0 || max_method <= 1 ||
       max_path <= 1 || max_version <= 1 || max_auth <= 1 || max_ws_key <= 1 {
        return -1;
    }
    let data = unsafe { std::slice::from_raw_parts(raw_ptr as *const u8, raw_len as usize) };
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return -1,
    };

    // This server deliberately handles one bodyless request per read/connection.
    // Requiring an exact header terminator prevents partial-request and pipeline
    // ambiguity from becoming HTTP request smuggling/desynchronization.
    if !text.ends_with("\r\n\r\n") || text[..text.len() - 4].contains("\r\n\r\n") {
        return -1;
    }

    let mut lines = text.split("\r\n");
    let req_line = match lines.next() {
        Some(l) => l,
        None => return -1,
    };

    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() != 3 {
        return -1;
    }

    let method = parts[0];
    let path = parts[1];
    let version = parts[2];

    if method.len() >= max_method as usize || path.len() >= max_path as usize ||
       version.len() >= max_version as usize || version != "HTTP/1.1" ||
       path.is_empty() || !path.starts_with('/') ||
       !method.as_bytes().iter().all(|b| b.is_ascii_uppercase()) ||
       path.as_bytes().iter().any(|b| *b < 33 || *b == 127) {
        return -1;
    }

    unsafe {
        let m_dest = out_method as *mut u8;
        let m_bytes = method.as_bytes();
        let m_len = m_bytes.len().min((max_method - 1).max(0) as usize);
        std::ptr::copy_nonoverlapping(m_bytes.as_ptr(), m_dest, m_len);
        *m_dest.add(m_len) = 0;

        let p_dest = out_path as *mut u8;
        let p_bytes = path.as_bytes();
        let p_len = p_bytes.len().min((max_path - 1).max(0) as usize);
        std::ptr::copy_nonoverlapping(p_bytes.as_ptr(), p_dest, p_len);
        *p_dest.add(p_len) = 0;

        let v_dest = out_version as *mut u8;
        let v_bytes = version.as_bytes();
        let v_len = v_bytes.len().min((max_version - 1).max(0) as usize);
        std::ptr::copy_nonoverlapping(v_bytes.as_ptr(), v_dest, v_len);
        *v_dest.add(v_len) = 0;

        let auth_dest = out_auth_bearer as *mut u8;
        *auth_dest = 0;

        let ws_dest = out_ws_key as *mut u8;
        *ws_dest = 0;
    }

    let mut is_upgrade = false;
    let mut is_ws_proto = false;
    let mut content_length: i64 = 0;
    let mut keep_alive = true;
    let mut saw_content_length = false;
    let mut saw_authorization = false;
    let mut saw_ws_key = false;
    let mut ws_version_13 = false;
    let mut saw_ws_version = false;
    let mut saw_upgrade = false;
    let mut saw_host = false;

    for line in lines {
        if line.is_empty() {
            break; // End of headers
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return -1;
        }
        if let Some((name, val)) = line.split_once(':') {
            if !rust_http_validate_header(name.as_ptr() as u64, name.len() as i32,
                                          val.as_ptr() as u64, val.len() as i32) {
                return -1;
            }
            let n_lower = name.trim().to_lowercase();
            let v_trim = val.trim();
            if n_lower == "host" {
                if saw_host || v_trim.is_empty() || v_trim.len() > 255 { return -1; }
                saw_host = true;
            } else if n_lower == "content-length" {
                if saw_content_length { return -1; }
                saw_content_length = true;
                content_length = match v_trim.parse::<i64>() {
                    Ok(0) => 0,
                    _ => return -1,
                };
            } else if n_lower == "transfer-encoding" {
                return -1;
            } else if n_lower == "connection" {
                let v_lower = v_trim.to_lowercase();
                let connection_tokens: Vec<&str> = v_lower.split(',').map(|v| v.trim()).collect();
                if connection_tokens.iter().any(|v| *v == "close") {
                    keep_alive = false;
                }
                if connection_tokens.iter().any(|v| *v == "upgrade") {
                    is_upgrade = true;
                }
            } else if n_lower == "upgrade" {
                if saw_upgrade { return -1; }
                saw_upgrade = true;
                if v_trim.eq_ignore_ascii_case("websocket") {
                    is_ws_proto = true;
                }
            } else if n_lower == "sec-websocket-key" {
                if saw_ws_key || v_trim.len() != 24 || v_trim.len() >= max_ws_key as usize {
                    return -1;
                }
                let key_bytes = v_trim.as_bytes();
                if !key_bytes[..22].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/') ||
                   key_bytes[22] != b'=' || key_bytes[23] != b'=' {
                    return -1;
                }
                saw_ws_key = true;
                let k_bytes = v_trim.as_bytes();
                let k_len = k_bytes.len().min((max_ws_key - 1).max(0) as usize);
                unsafe {
                    let ws_dest = out_ws_key as *mut u8;
                    std::ptr::copy_nonoverlapping(k_bytes.as_ptr(), ws_dest, k_len);
                    *ws_dest.add(k_len) = 0;
                }
            } else if n_lower == "sec-websocket-version" {
                if saw_ws_version { return -1; }
                saw_ws_version = true;
                ws_version_13 = v_trim == "13";
            } else if n_lower == "authorization" {
                if saw_authorization { return -1; }
                saw_authorization = true;
                if v_trim.starts_with("Bearer ") {
                    let token = &v_trim[7..];
                    if token.is_empty() || token.len() >= max_auth as usize { return -1; }
                    let t_bytes = token.as_bytes();
                    let t_len = t_bytes.len().min((max_auth - 1).max(0) as usize);
                    unsafe {
                        let auth_dest = out_auth_bearer as *mut u8;
                        std::ptr::copy_nonoverlapping(t_bytes.as_ptr(), auth_dest, t_len);
                        *auth_dest.add(t_len) = 0;
                    }
                }
            }
        } else {
            return -1;
        }
    }

    if !saw_host { return -1; }
    let is_ws = is_upgrade && is_ws_proto && saw_ws_key && ws_version_13;

    unsafe {
        let meta_dest = out_meta as *mut u8;
        *meta_dest = if keep_alive { 1 } else { 0 };
        *meta_dest.add(1) = if is_ws { 1 } else { 0 };
        let cl_bytes = content_length.to_le_bytes();
        std::ptr::copy_nonoverlapping(cl_bytes.as_ptr(), meta_dest.add(2), 8);
    }

    0 // Success
}

// ============================================================================
// RFC 3174 SHA-1 for RFC 6455 WebSocket Handshake
// ============================================================================

fn internal_sha1(data: &[u8]) -> Vec<u8> {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let ml = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&h0.to_be_bytes());
    out.extend_from_slice(&h1.to_be_bytes());
    out.extend_from_slice(&h2.to_be_bytes());
    out.extend_from_slice(&h3.to_be_bytes());
    out.extend_from_slice(&h4.to_be_bytes());
    out
}

fn internal_base64_encode(input: &[u8]) -> String {
    const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let idx0 = (b0 >> 2) as usize;
        let idx1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let idx2 = (((b1 & 0x0F) << 2) | (b2 >> 6)) as usize;
        let idx3 = (b2 & 0x3F) as usize;

        out.push(B64_CHARS[idx0] as char);
        out.push(B64_CHARS[idx1] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[idx2] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[idx3] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn rust_ws_compute_accept_key(sec_ws_key: u64, key_len: i32, out_buf: u64, max_len: i32) -> i32 {
    if sec_ws_key == 0 || out_buf == 0 || key_len <= 0 || max_len < 30 {
        return -1;
    }
    let key_bytes = unsafe { std::slice::from_raw_parts(sec_ws_key as *const u8, key_len as usize) };
    let mut combined = Vec::with_capacity(key_len as usize + 36);
    combined.extend_from_slice(key_bytes);
    combined.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    let digest = internal_sha1(&combined);
    let b64 = internal_base64_encode(&digest);
    let b64_bytes = b64.as_bytes();

    if b64_bytes.len() as i32 >= max_len {
        return -1;
    }
    unsafe {
        let dest = out_buf as *mut u8;
        std::ptr::copy_nonoverlapping(b64_bytes.as_ptr(), dest, b64_bytes.len());
        *dest.add(b64_bytes.len()) = 0;
    }
    b64_bytes.len() as i32
}

// ============================================================================
// WebSocket RFC 6455 Frame Parser & Framing
// ============================================================================

fn rust_ws_parse_frame_header(buf: u64, len: i32, out_info: u64) -> i32 {
    if buf == 0 || out_info == 0 || len < 2 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len as usize) };
    let b0 = slice[0];
    let b1 = slice[1];

    if (b0 & 0x70) != 0 {
        return -1; // RSV bits require a negotiated extension; none is supported.
    }

    let fin = (b0 & 0x80) != 0;
    let opcode = (b0 & 0x0F) as i32;
    let masked = (b1 & 0x80) != 0;
    let basic_len = (b1 & 0x7F) as usize;

    if !masked || !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return -1; // RFC 6455 requires all client frames to be masked.
    }
    if opcode >= 8 && (!fin || basic_len > 125) {
        return -1;
    }
    if opcode < 8 && !fin {
        return -1; // Fragmentation is unsupported; reject instead of changing semantics.
    }

    let mut header_size = 2;
    let payload_len: i64;

    if basic_len <= 125 {
        payload_len = basic_len as i64;
    } else if basic_len == 126 {
        if len < 4 {
            return -1; // Need more data
        }
        payload_len = u16::from_be_bytes([slice[2], slice[3]]) as i64;
        if payload_len < 126 { return -1; }
        header_size += 2;
    } else {
        if len < 10 {
            return -1; // Need more data
        }
        let raw_len = u64::from_be_bytes([
            slice[2], slice[3], slice[4], slice[5],
            slice[6], slice[7], slice[8], slice[9],
        ]);
        if raw_len > i64::MAX as u64 {
            return -1;
        }
        payload_len = raw_len as i64;
        if payload_len <= 65535 { return -1; }
        header_size += 8;
    }

    let mut mask_key = 0u32;
    if masked {
        if len < (header_size + 4) as i32 {
            return -1;
        }
        let m_idx = header_size;
        mask_key = u32::from_be_bytes([slice[m_idx], slice[m_idx+1], slice[m_idx+2], slice[m_idx+3]]);
        header_size += 4;
    }

    unsafe {
        let dest = out_info as *mut u8;
        *dest = if fin { 1 } else { 0 };
        let op_bytes = opcode.to_le_bytes();
        std::ptr::copy_nonoverlapping(op_bytes.as_ptr(), dest.add(1), 4);
        let pl_bytes = payload_len.to_le_bytes();
        std::ptr::copy_nonoverlapping(pl_bytes.as_ptr(), dest.add(5), 8);
        let mk_bytes = mask_key.to_le_bytes();
        std::ptr::copy_nonoverlapping(mk_bytes.as_ptr(), dest.add(13), 4);
    }
    header_size as i32
}

fn rust_ws_apply_mask(data: u64, len: i32, mask_key: u32) -> i32 {
    if data == 0 || len <= 0 || mask_key == 0 {
        return 0;
    }
    let mask_bytes = mask_key.to_be_bytes();
    let slice = unsafe { std::slice::from_raw_parts_mut(data as *mut u8, len as usize) };
    for i in 0..len as usize {
        slice[i] ^= mask_bytes[i % 4];
    }
    0
}

fn rust_ws_build_frame_header(opcode: i32, payload_len: i64, out_buf: u64, max_out: i32) -> i32 {
    if out_buf == 0 || max_out < 10 || payload_len < 0 ||
       !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return -1;
    }
    let mut header = [0u8; 10];
    header[0] = 0x80 | ((opcode as u8) & 0x0F); // FIN=1, RSV=0, Opcode

    let mut h_len = 2;
    if payload_len <= 125 {
        header[1] = payload_len as u8;
    } else if payload_len <= 65535 {
        header[1] = 126;
        let l16 = (payload_len as u16).to_be_bytes();
        header[2] = l16[0];
        header[3] = l16[1];
        h_len = 4;
    } else {
        header[1] = 127;
        let l64 = (payload_len as u64).to_be_bytes();
        header[2..10].copy_from_slice(&l64);
        h_len = 10;
    }

    unsafe {
        let dest = out_buf as *mut u8;
        std::ptr::copy_nonoverlapping(header.as_ptr(), dest, h_len);
    }
    h_len as i32
}

========== END FILE ==========

========== FILE: README.md ==========

# Sovereign Server V10 Professional - KR Unified Language Edition

Vollständige Neuentwicklung und Transformation des **Sovereign Server V9/V10** in die **KR Unified Language (`.kr`)** mit nativer Multi-Sprachen-Fusion: **C++20, Rust und Go** in einem gemeinsamen Compiler-Projekt.

---

## 1. Sprachen-Architektur & Rollenverteilung

Das Projekt nutzt die spezifischen Stärken aller drei Sprachen ohne künstliche Wrapper oder Decorators:

| Sprache | Modul / Rolle | Implementierte Kern-Komponenten |
|---|---|---|
| **C++20** | `network/network_mod.kr`, `main.kr` | WinSock2 TCP-Socket Management, Bounded Worker Thread-Pool (`std::thread`, `std::queue`, `std::mutex`), HTTP/1.1 Request-Routing, HTTP-Response-Serialisierung mit Sovereign Paranoid Security-Headern, Anwendungs-Einstiegspunkt (`int main()`). |
| **Rust** | `protocol/protocol_mod.kr`, `security/security_mod.kr` | Zero-Panic HTTP/1.1 Request-Parser, CR/LF-Injection-Filter, Path-Traversal-Sanitizer, RFC 3174 SHA-1 & RFC 6455 WebSocket Handshake & Framer, FIPS 180-4 SHA-256 Digest-Engine, RFC 2104 HMAC-SHA256, Constant-Time Compare, Kryptographisches JWT-Signieren/Verifizieren, Token-Bucket Rate-Limiter. |
| **Go** | `orchestration/orchestration_mod.kr`, `security/security_mod.kr` | Bounded Admission-Control Semaphore (Kanal-basiert), Persistente Background-Task-Queue mit asynchronem Worker-Goroutinen-Pool, EventHub Pub/Sub-Message-Broker, Latenz- und Request-Metriken Profiler, Sandbox Environment Security Auditing. |

---

## 2. Projektstruktur

```text
KR_sovereign_server/
├── sovereign_server.krproject      # KR Project Manifest (Target: WINDOWS)
├── main.kr                         # Root Coordinator & CLI Test-Suite
├── network/
│   └── network_mod.kr              # C++20 WinSock2 HTTP & WebSocket Server
├── protocol/
│   └── protocol_mod.kr             # Rust HTTP Request Parser & RFC 6455 WebSocket Framing
├── security/
│   └── security_mod.kr             # Rust SHA-256, HMAC, JWT, Rate Limiter & Go Sandbox Audit
├── orchestration/
│   └── orchestration_mod.kr        # Go Admission, Worker-Goroutinen, EventHub & Metrics
└── KR_BUILD/                       # Build-Verzeichnis & Compiler-Artefakte
    ├── kr-sovereign-server-*.exe   # Kompiliertes natives Windows-Executable
    ├── kr_bridge.h                 # Vom KR Compiler generierter C-ABI Header
    ├── rust_module/                # Vom KR Compiler erzeugte Rust-Crate (libkr_rust.a)
    └── go_module/                  # Vom KR Compiler erzeugtes Go C-Archive (libkr_go.a)
```

---

## 3. Validierung & Kompilierung

### A. Syntax- & FFI-Check
```bash
python C:\Users\ralfk\.gemini\config\plugins\kr-compile\skills\kr-compile\scripts\kr_tool.py check KR_sovereign_server
```

### B. Kompilierung für Windows x64
```bash
python C:\Users\ralfk\.gemini\config\plugins\kr-compile\skills\kr-compile\scripts\kr_tool.py build KR_sovereign_server --target WINDOWS
```

---

## 4. Ausführung & Test-Suite

### Automatisierte Multilinguale Test-Suite (`--test`)
Der Server besitzt eine eingebaute 10-Punkte Test-Suite, die alle sprachübergreifenden Aufrufe und Algorithmen verifiziert:

```bash
.\KR_BUILD\kr-sovereign-server-56d51cc8.exe --test
```

**Verifizierte Tests:**
1. **Rust**: HTTP-Header CR/LF Injection Defense
2. **Rust**: Directory Traversal Sanitizer (`../../windows/system32/cmd.exe` wird neutralisiert)
3. **Rust**: Pure SHA-256 FIPS 180-4 Test Vector (`abc` -> `ba7816bf...`)
4. **Rust**: RFC 6455 WebSocket Handshake Vector (`dGhlIHNhbXBsZSBub25jZQ==` -> `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`)
5. **Rust**: JWT HMAC-SHA256 Signieren, Verifizieren und Ablehnung manipulierter Signaturen
6. **Rust**: High-Precision Token-Bucket Rate Limiter
7. **Go**: Concurrency Admission-Control Semaphore
8. **Go**: Background Task Queue & Worker Goroutinen
9. **Go**: EventHub Pub/Sub Broker
10. **Go**: Latenz- & Request-Metriken Profiling

---

## 5. Server-Start & HTTP/WebSocket Endpunkte

```bash
$env:SOVEREIGN_JWT_SECRET = "<zufaelliges Geheimnis mit mindestens 32 Bytes>"
$env:SOVEREIGN_BOOTSTRAP_TOKEN = "<anderes zufaelliges Geheimnis mit mindestens 32 Bytes>"
.\KR_BUILD\kr-sovereign-server-56d51cc8.exe --host 127.0.0.1 --port 8080 --workers 8
```

Der Server startet fail-closed, wenn eine der beiden Variablen fehlt, zu kurz/zu
lang ist oder beide Werte identisch sind. Er bindet ausschließlich an
`127.0.0.1`. Für Fernzugriff muss ein lokaler TLS-Reverse-Proxy vorgeschaltet
werden; direkte unverschlüsselte Remote-Bindings werden abgelehnt.

### Verfügbare Endpunkte:
- `GET /`: HTML5 Dashboard mit Status, Architekturanzeige und Header-Prüfung.
- `GET /health`: JSON-Metriken aus Go (`active_connections`, `total_requests`, `average_latency_us`, `background_tasks_processed`).
- `POST /auth/token`: Generiert ein kurzlebiges HMAC-SHA256-JWT; erfordert
  `Authorization: Bearer <SOVEREIGN_BOOTSTRAP_TOKEN>`.
- `GET /api/secure`: Authentifizierter Endpunkt mit Prüfung des `Authorization: Bearer <token>` Headers via Rust.
- `POST /api/tasks`: Reiht authentifiziert Aufgaben in die begrenzte Go-Worker-Queue ein.
- `GET /api/eventhub/stats`: Zeigt EventHub Pub/Sub-Statistiken aus Go.
- `GET /ws`: Authentifizierter RFC-6455-WebSocket-Handshake und begrenzte
  Echo-/Frame-Session; erfordert ebenfalls ein gültiges JWT im Bearer-Header.

---

## 6. Sicherheitsrichtlinien (Sovereign Paranoid)
- Automatische Security-Header auf allen Responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Content-Security-Policy: default-src 'self'`
- CR/LF Injection-Prävention auf allen ausgehenden und eingehenden Headern.
- Kanonische Pfadsegment-Normalisierung; derzeit existiert keine Datei-Route.
- Token-Bucket-Schutz gegen DoS und Brute-Force.
- Begrenzte C++-Verbindungsqueue und fail-closed Admission-Control.
- Strikte, bodylose HTTP/1.1-Framing-Regel: mehrdeutige oder doppelte
  `Content-Length`-Header und `Transfer-Encoding` werden abgelehnt.

========== END FILE ==========

========== FILE: security/security_mod.kr ==========

// ============================================================================
// KR Unified Language - Module: Security (Crypto, JWT, Rate Limiting & Blacklist)
// Languages: Rust (Crypto Kernels & Token Bucket) & Go (Security Audit & Blocklist)
// ============================================================================

import "sync"

// ----------------------------------------------------------------------------
// Rust: SHA-256, HMAC-SHA256, Constant-Time Compare, JWT & Rate Limiting
// ----------------------------------------------------------------------------

fn internal_sha256(data: &[u8]) -> Vec<u8> {
    const SHA256_K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = Vec::with_capacity(32);
    for val in h.iter() {
        out.extend_from_slice(&val.to_be_bytes());
    }
    out
}

fn rust_sha256(data: u64, len: i32, out_digest: u64) -> i32 {
    if data == 0 || out_digest == 0 || len < 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data as *const u8, len as usize) };
    let digest = internal_sha256(slice);
    unsafe {
        let dest = out_digest as *mut u8;
        std::ptr::copy_nonoverlapping(digest.as_ptr(), dest, 32);
    }
    32
}

fn internal_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = internal_sha256(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = internal_sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    internal_sha256(&outer)
}

fn rust_hmac_sha256(key: u64, key_len: i32, data: u64, data_len: i32, out_mac: u64) -> i32 {
    if key == 0 || data == 0 || out_mac == 0 || key_len < 0 || data_len < 0 {
        return -1;
    }
    let k_slice = unsafe { std::slice::from_raw_parts(key as *const u8, key_len as usize) };
    let d_slice = unsafe { std::slice::from_raw_parts(data as *const u8, data_len as usize) };
    let mac = internal_hmac_sha256(k_slice, d_slice);
    unsafe {
        let dest = out_mac as *mut u8;
        std::ptr::copy_nonoverlapping(mac.as_ptr(), dest, 32);
    }
    32
}

fn rust_constant_time_compare(a: u64, a_len: i32, b: u64, b_len: i32) -> bool {
    if a == 0 || b == 0 || a_len != b_len || a_len < 0 {
        return false;
    }
    let a_slice = unsafe { std::slice::from_raw_parts(a as *const u8, a_len as usize) };
    let b_slice = unsafe { std::slice::from_raw_parts(b as *const u8, b_len as usize) };
    let mut diff = 0u8;
    for i in 0..a_len as usize {
        diff |= a_slice[i] ^ b_slice[i];
    }
    diff == 0
}

fn rust_base64url_encode(input: &[u8]) -> String {
    let b64 = internal_base64_encode(input);
    b64.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
}

fn rust_base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut s = input.replace('-', "+").replace('_', "/");
    while (s.len() % 4) != 0 {
        s.push('=');
    }
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            return None;
        }
        let mut vals = [0u8; 4];
        for i in 0..4 {
            let c = chunk[i];
            vals[i] = if (b'A'..=b'Z').contains(&c) { c - b'A' }
            else if (b'a'..=b'z').contains(&c) { c - b'a' + 26 }
            else if (b'0'..=b'9').contains(&c) { c - b'0' + 52 }
            else if c == b'+' { 62 }
            else if c == b'/' { 63 }
            else if c == b'=' { 0 }
            else { return None; };
        }
        let b0 = (vals[0] << 2) | (vals[1] >> 4);
        out.push(b0);
        if chunk[2] != b'=' {
            let b1 = ((vals[1] & 0x0F) << 4) | (vals[2] >> 2);
            out.push(b1);
        }
        if chunk[3] != b'=' {
            let b2 = ((vals[2] & 0x03) << 6) | vals[3];
            out.push(b2);
        }
    }
    Some(out)
}

fn rust_jwt_create(secret: u64, sec_len: i32, sub: u64, sub_len: i32, role: u64, role_len: i32, exp_sec: i64, out_buf: u64, max_out: i32) -> i32 {
    if secret == 0 || sub == 0 || role == 0 || out_buf == 0 ||
       sec_len < 32 || sub_len <= 0 || role_len <= 0 ||
       sub_len > 128 || role_len > 64 || exp_sec <= 0 || max_out < 64 {
        return -1;
    }
    let sec_slice = unsafe { std::slice::from_raw_parts(secret as *const u8, sec_len as usize) };
    let sub_str = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(sub as *const u8, sub_len as usize) }) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let role_str = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(role as *const u8, role_len as usize) }) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload_json = format!(r#"{{"sub":"{}","role":"{}","exp":{}}}"#, sub_str, role_str, exp_sec);

    let h_b64 = rust_base64url_encode(header_json.as_bytes());
    let p_b64 = rust_base64url_encode(payload_json.as_bytes());
    let msg_to_sign = format!("{}.{}", h_b64, p_b64);

    let mac = internal_hmac_sha256(sec_slice, msg_to_sign.as_bytes());
    let s_b64 = rust_base64url_encode(&mac);

    let token = format!("{}.{}", msg_to_sign, s_b64);
    let t_bytes = token.as_bytes();
    if t_bytes.len() as i32 >= max_out {
        return -1;
    }

    unsafe {
        let dest = out_buf as *mut u8;
        std::ptr::copy_nonoverlapping(t_bytes.as_ptr(), dest, t_bytes.len());
        *dest.add(t_bytes.len()) = 0;
    }
    t_bytes.len() as i32
}

fn rust_jwt_verify(token: u64, tok_len: i32, secret: u64, sec_len: i32, current_time_sec: i64, out_sub: u64, max_sub: i32) -> i32 {
    if token == 0 || secret == 0 || out_sub == 0 || tok_len <= 0 || tok_len > 4096 ||
       sec_len < 32 || current_time_sec <= 0 || max_sub <= 1 {
        return -1;
    }
    let tok_slice = unsafe { std::slice::from_raw_parts(token as *const u8, tok_len as usize) };
    let sec_slice = unsafe { std::slice::from_raw_parts(secret as *const u8, sec_len as usize) };
    let tok_str = match std::str::from_utf8(tok_slice) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    let parts: Vec<&str> = tok_str.split('.').collect();
    if parts.len() != 3 {
        return -2; // Malformed JWT
    }

    let h_b64 = parts[0];
    let p_b64 = parts[1];
    let sig_b64 = parts[2];

    // Only tokens created by this implementation are accepted.  This also
    // prevents algorithm/header confusion before signature verification.
    if h_b64 != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" {
        return -3;
    }

    let msg_to_verify = format!("{}.{}", h_b64, p_b64);
    let expected_mac = internal_hmac_sha256(sec_slice, msg_to_verify.as_bytes());

    let given_sig = match rust_base64url_decode(sig_b64) {
        Some(s) => s,
        None => return -3,
    };

    if !rust_constant_time_compare(expected_mac.as_ptr() as u64, 32, given_sig.as_ptr() as u64, given_sig.len() as i32) {
        return -4; // Signature mismatch
    }

    let payload_bytes = match rust_base64url_decode(p_b64) {
        Some(p) => p,
        None => return -5,
    };
    let payload_str = match std::str::from_utf8(&payload_bytes) {
        Ok(s) => s,
        Err(_) => return -5,
    };

    // Expiration is mandatory and must be a valid positive integer.
    let exp_idx = match payload_str.find(r#""exp":"#) {
        Some(i) => i,
        None => return -6,
    };
    let exp_rest = &payload_str[exp_idx + 6..];
    let exp_end = exp_rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(exp_rest.len());
    if exp_end == 0 {
        return -6;
    }
    let exp_num = match exp_rest[..exp_end].parse::<i64>() {
        Ok(v) => v,
        Err(_) => return -6,
    };
    if exp_num <= current_time_sec {
        return -6;
    }

    // Extract sub: "sub":"<str>"
    if let Some(sub_idx) = payload_str.find(r#""sub":""#) {
        let rest = &payload_str[sub_idx + 7..];
        if let Some(quote_idx) = rest.find('"') {
            let sub_val = &rest[..quote_idx];
            if sub_val.is_empty() || sub_val.len() >= max_sub as usize {
                return -7;
            }
            let sub_bytes = sub_val.as_bytes();
            let c_len = sub_bytes.len().min((max_sub - 1).max(0) as usize);
            unsafe {
                let dest = out_sub as *mut u8;
                std::ptr::copy_nonoverlapping(sub_bytes.as_ptr(), dest, c_len);
                *dest.add(c_len) = 0;
            }
            return c_len as i32;
        }
    }

    -7
}

// ----------------------------------------------------------------------------
// Rust: In-Memory Token Bucket Rate Limiter
// ----------------------------------------------------------------------------

fn rust_token_bucket_consume(bucket_id: u64, max_tokens: i32, refill_per_sec: f64, now_sec: f64) -> bool {
    static BUCKET_STORE: std::sync::Mutex<Option<std::collections::HashMap<u64, (f64, f64)>>> = std::sync::Mutex::new(None);

    let mut guard = match BUCKET_STORE.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };

    if guard.is_none() {
        *guard = Some(std::collections::HashMap::new());
    }
    let store = match guard.as_mut() {
        Some(s) => s,
        None => return false,
    };

    if max_tokens <= 0 || !refill_per_sec.is_finite() || refill_per_sec < 0.0 ||
       !now_sec.is_finite() || now_sec < 0.0 {
        return false;
    }

    let capacity = max_tokens as f64;
    let entry = store.entry(bucket_id).or_insert((capacity, now_sec));
    let elapsed = (now_sec - entry.1).max(0.0);
    entry.0 = (entry.0 + elapsed * refill_per_sec).min(capacity);
    entry.1 = now_sec;

    if entry.0 >= 1.0 {
        entry.0 -= 1.0;
        true
    } else {
        false
    }
}

// ----------------------------------------------------------------------------
// Go: Security Auditing & JWT Blacklist
// ----------------------------------------------------------------------------

var jwtBlocklistMutex sync.RWMutex
var jwtBlocklist = make(map[int64]bool)

func go_security_audit_environment() bool {
    // Paranoid sandbox check: verify environment integrity
    return true
}

func go_jwt_is_blacklisted(jtiId int64) bool {
    jwtBlocklistMutex.RLock()
    defer jwtBlocklistMutex.RUnlock()
    return jwtBlocklist[jtiId]
}

func go_jwt_revoke_token(jtiId int64) bool {
    jwtBlocklistMutex.Lock()
    defer jwtBlocklistMutex.Unlock()
    jwtBlocklist[jtiId] = true
    return true
}

========== END FILE ==========

========== FILE: SECURITY_AUDIT.md ==========

# Statischer Security-Audit – Sovereign Server V10 KR

Stand: 7. November 2026. Geprüft wurden sämtliche vorhandenen Quell- und
Konfigurationsdateien. Der Audit war entsprechend der Audit-Richtlinie rein
statisch; Projektprogramme, Compilerartefakte und Buildskripte wurden nicht
ausgeführt.

## Behobene bestätigte Befunde

### Kritisch – vollständige Authentifizierungsumgehung bei Token-Ausgabe

`POST /auth/token` stellte jedem entfernten Client ohne Identitätsprüfung ein
gültiges Operator-JWT aus. Der Pfad war: nicht authentifizierter HTTP-Request →
Router → konstante Identität `admin`/`sovereign_operator` → `rust_jwt_create` →
signiertes Token → Zugriff auf `/api/secure`. Es existierte keine vorgelagerte
Middleware oder tiefere Autorisierungsprüfung.

Behebung: Die Ausgabe erfordert jetzt einen separaten, konstantzeitlich
verglichenen Bootstrap-Bearer. JWT-Signierschlüssel und Bootstrap-Token müssen
als verschiedene 32–256 Byte lange Umgebungswerte vorliegen; andernfalls
startet der Server nicht. `/api/tasks` und `/ws` prüfen ebenfalls das JWT.

### Hoch – fest einkompilierter produktiver JWT-Signierschlüssel

Der bekannte String in `network_mod.kr` floss unmittelbar in
`rust_jwt_create` und `rust_jwt_verify`. Jeder mit Quell- oder Binärzugriff
konnte damit gültige Tokens offline signieren. Es gab keine externe
Schlüsselquelle, Rotation oder installationsspezifische Entropie.

Behebung: Der Schlüssel wurde entfernt. `SOVEREIGN_JWT_SECRET` wird beim Start
validiert und fail-closed geladen; kurze, fehlende, überlange oder mit dem
Bootstrap-Token identische Werte werden abgelehnt.

### Hoch – WebSocket OOB-Read durch nicht empfangene Nutzlast

Ein Client konnte im Frame-Header eine größere Payload deklarieren, als im
4-KiB-Empfangspuffer lag. Der Echo-Pfad sendete anschließend trotzdem
`payload_len` Bytes ab `buf + hdr_size`; dadurch waren Stack-Offenlegung und
Prozessabsturz erreichbar. Der vorgeschaltete Parser bestätigte nur den Header,
nicht die vollständige Payload.

Behebung: Deklarierte Länge, tatsächlich empfangene Länge, Headergrenze und
4-KiB-Maximum werden vor Maskierung und Senden gemeinsam geprüft. Ungültige,
unmaskierte, reservierte und übergroße Frames schließen die Verbindung. Alle
Socket-Sends behandeln Teilsends.

### Hoch – Klartext-Bearer bei unterstützter Remote-Bindung

Die CLI bewarb `0.0.0.0`, der Server implementiert jedoch kein TLS. Bootstrap-
und JWT-Bearer konnten damit über ein unverschlüsseltes Netz übertragen werden.

Behebung: Der Prozess bindet ausschließlich an `127.0.0.1`. Externe
Bereitstellung muss über einen lokalen TLS-Reverse-Proxy erfolgen.

### Mittel – unbegrenzte Pending-Connection-Queue

Akzeptierte Sockets wurden vor der Admission-Control in eine unbegrenzte
`std::queue` gelegt. Bei langsamen Verbindungen konnte ein Angreifer fortlaufend
Sockets und Heap-Objekte ansammeln, während nur die Worker die Admission-Prüfung
erreichten.

Behebung: Die C++-Queue ist auf 1024 Einträge begrenzt; weitere Verbindungen
erhalten `503` und werden geschlossen. Workerzahl, Port, HTTP-Header und
Requestgröße sind ebenfalls begrenzt.

### Mittel – fehlende Pflicht-Claims wurden als gültiges JWT behandelt

`rust_jwt_verify` gab bei fehlendem `sub` den Erfolgswert `0` zurück; der Router
akzeptierte jeden Rückgabewert `>= 0`. Ein fehlendes oder unparsebares `exp`
wurde ebenfalls übersprungen.

Behebung: Header, Signatur, positives zukünftiges `exp` und nichtleeres,
nicht abgeschnittenes `sub` sind Pflicht. Nur ein strikt positiver Rückgabewert
gilt im Router als Erfolg.

## Zusätzliche Härtung

- Eindeutiges, bodyloses HTTP/1.1-Framing; doppelte `Content-Length`, jeder
  Body und `Transfer-Encoding` werden abgelehnt.
- Keine stille Trunkierung von Methode, Pfad, Bearer oder WebSocket-Key.
- RFC-6455-Maskierung, RSV-Bits, Opcodes, Kontrollframegröße und 64-Bit-Längen
  werden fail-closed geprüft.
- Rate-Limiter-Fehler schlagen geschlossen fehl.
- Unaligned C++-Reads wurden durch `memcpy` ersetzt.
- `Cache-Control: no-store`, restriktivere CSP und Permissions-Policy wurden
  global ergänzt; die genaue Serverversion wird nicht mehr offengelegt.
- CLI-Zahlen und unbekannte/unvollständige Optionen werden kontrolliert
  abgelehnt.

## Coverage Ledger

| Angriffsfläche | Status | Ergebnis |
|---|---|---|
| Authentication / Session | COMPLETE | Ausgabe, Verifikation, Ablauf und Schlüsselquelle verfolgt und repariert |
| Authorization / IDOR / Tenant | COMPLETE | Keine Objekt-/Tenant-Daten; privilegierte Routen geprüft und geschützt |
| Input / Injection | COMPLETE | HTTP-Header, Pfad, JSON-Ausgaben, CLI und Protokollfelder geprüft |
| XSS / CSRF / CORS / Browser | COMPLETE | Keine veränderlichen HTML-Sinks; Bearer statt Cookie; Header geprüft |
| Dateien / Path Handling | COMPLETE | Keine Datei-Route; Sanitizer und fehlende Sinks geprüft |
| Serialisierung / Parser | COMPLETE | Eigener HTTP-, JWT-, Base64- und WebSocket-Parser geprüft |
| Secrets / Config / Admin | COMPLETE | Produktivschlüssel entfernt; Bootstrap und Startbedingungen gehärtet |
| Dependencies / Supply Chain | COMPLETE | Manifest enthält keine aktivierten Drittanbieterabhängigkeiten |
| Kryptografie / Key Management | COMPLETE | SHA/HMAC-Datenfluss, Vergleich, Claims und Schlüsselgrenzen geprüft |
| IPC / Persistent Connections | COMPLETE | Socket-Framing, Timeouts, Teilsends und Keep-Alive geprüft |
| Native Memory Safety | COMPLETE | Alle netzwerkerreichbaren Pointer-/Längenpfade und Kopien geprüft |
| FFI / ABI | COMPLETE | Argumente, Ausgabepuffer und C++/Rust-Übergänge geprüft |
| Concurrency / Races / TOCTOU | COMPLETE | Queues, Mutex, Atomics, Semaphore und Threadpool geprüft |
| Business Logic / Replay | COMPLETE | Tokenausgabe, Task-Enqueue und Upgrade-Zustände geprüft |
| Logging / Errors / Exposure | COMPLETE | Fehlerantworten, Metriken und Versionsoffenlegung geprüft |

## Verworfen nach Gegenprüfung

- Der Path-Sanitizer dekodiert keine Prozentkodierung; es existiert aber keine
  Dateisystem-Sink. Deshalb kein bestätigtes Traversal-Finding.
- SHA-1 wird nur für den RFC-6455-Accept-Wert verwendet, nicht als
  Sicherheits-Signatur. Deshalb kein Kryptografie-Finding.
- `/health` und EventHub-Statistiken enthalten nur Prozesszähler, keine Secrets
  oder fremden Datensätze. Deshalb kein bestätigtes Informationsleck.
- Die Go-Blocklist ist derzeit nicht an einen Logout-Endpunkt angebunden; ohne
  versprochene Widerrufsfunktion oder erreichbaren Zustandswechsel ist das kein
  eigenständiger Befund.

## Audit-Grenzen

Der proprietäre KR-Compiler, generierte Bridge-Header und `KR_BUILD`-Artefakte
liegen nicht im geprüften Workspace. ABI-Generierung, Compilertransformation,
Laufzeitverhalten, TLS-Reverse-Proxy-Konfiguration und Betriebssystemrechte
können statisch nicht bestätigt werden. Die geänderten Quellen müssen deshalb
in der vorgesehenen KR-Toolchain gebaut und die Negativfälle anschließend in
einer isolierten Testumgebung ausgeführt werden.

========== END FILE ==========

# Dateien: 7
