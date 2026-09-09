#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

using Bytes = std::vector<std::uint8_t>;
using Row = std::map<std::string, std::string>;

constexpr const char *kClientId = "publisher-001";
constexpr const char *kKemMain = OQS_KEM_alg_ml_kem_768;
constexpr const char *kSigMain = OQS_SIG_alg_ml_dsa_65;
constexpr const char *kCheckpointSigningDomain = "AAPA-MQTT-CHECKPOINT-V2|";
constexpr const char *kWitnessSigningDomain = "AAPA-MQTT-WITNESS-V2|";
constexpr std::size_t kHashBytes = 32;

struct Options {
    std::string mode = "quick";
    std::string exp = "all";
    std::string out_dir;
    int runs = 100;
    int audit_runs = 100;
    int warmup = 5;
    std::size_t payload_bytes = 128;
    bool legacy_names = false;
    bool selftest = false;
};

struct Provenance {
    std::string env_id;
    std::string run_id;
    std::string timestamp_utc;
    std::string mode;
    std::string config_hash;
    std::string seed;
    std::string git_commit;
    std::string dependency_hash;
    std::string source_tree_hash;
    std::string source_script = "cpp/aapa_crypto_bench.cpp";
    fs::path result_dir;
};

struct Stats {
    double mean = 0.0;
    double median = 0.0;
    double p95 = 0.0;
    double stdev = 0.0;
    double min = 0.0;
    double max = 0.0;
    double ci95_low = 0.0;
    double ci95_high = 0.0;
    double throughput_ops_s = 0.0;
    std::size_t n = 0;
};

static std::string format_double(double value, int precision = 6) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(precision) << value;
    return oss.str();
}

static std::string now_utc() {
    const auto now = std::chrono::system_clock::now();
    const auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

static double now_unix_double() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration<double>(now).count();
}

static std::string getenv_or(const char *name, const std::string &fallback = "") {
    const char *value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return std::string(value);
}

static std::string safe_id(std::string value) {
    for (char &c : value) {
        const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.';
        if (!ok) {
            c = '_';
        }
    }
    while (!value.empty() && value.front() == '_') {
        value.erase(value.begin());
    }
    while (!value.empty() && value.back() == '_') {
        value.pop_back();
    }
    return value.empty() ? "run" : value;
}

static fs::path repo_root_from_exe_hint() {
    fs::path cwd = fs::current_path();
    for (int i = 0; i < 8; ++i) {
        if (fs::exists(cwd / "experiments" / "env.json")) {
            return cwd;
        }
        if (!cwd.has_parent_path()) {
            break;
        }
        cwd = cwd.parent_path();
    }
    return fs::current_path();
}

static std::string read_env_id(const fs::path &repo_root) {
    const fs::path env_path = repo_root / "experiments" / "env.json";
    std::ifstream in(env_path);
    if (!in) {
        return "unknown-env";
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    const std::regex re(R"ENV("env_id"\s*:\s*"([^"]+)")ENV");
    std::smatch match;
    if (std::regex_search(text, match, re) && match.size() > 1) {
        return match[1].str();
    }
    return "unknown-env";
}

static Provenance make_provenance(const Options &opt) {
    const fs::path repo_root = repo_root_from_exe_hint();
    Provenance p;
    p.env_id = read_env_id(repo_root);
    p.mode = getenv_or("AAPA_MODE", opt.mode);
    p.timestamp_utc = getenv_or("AAPA_TIMESTAMP_UTC", now_utc());
    p.run_id = getenv_or("AAPA_RUN_ID", "stage4-cpp-" + p.mode + "-" + p.timestamp_utc);
    p.config_hash = getenv_or("AAPA_CONFIG_HASH", "unregistered");
    p.seed = getenv_or("AAPA_SEED", "0");
    p.git_commit = getenv_or("AAPA_GIT_COMMIT", "unregistered");
    p.dependency_hash = getenv_or("AAPA_DEPENDENCY_HASH", "unregistered");
    p.source_tree_hash = getenv_or("AAPA_SOURCE_TREE_HASH", "unregistered");

    const std::string env_out = getenv_or("AAPA_RESULT_DIR");
    if (!opt.out_dir.empty()) {
        p.result_dir = fs::absolute(opt.out_dir);
    } else if (!env_out.empty()) {
        p.result_dir = fs::absolute(env_out);
    } else {
        const std::string parent = p.mode == "full" ? "stage4_full" : "stage4_nonfull";
        p.result_dir = repo_root / "experiments" / "results" / parent / safe_id(p.run_id);
    }
    fs::create_directories(p.result_dir);
    return p;
}

static std::string csv_escape(const std::string &s) {
    const bool quote = s.find_first_of(",\"\n\r") != std::string::npos;
    if (!quote) {
        return s;
    }
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') {
            out += "\"\"";
        } else {
            out += c;
        }
    }
    out += '"';
    return out;
}

static void add_provenance(Row &row, const Provenance &p) {
    row["env_id"] = p.env_id;
    row["run_id"] = p.run_id;
    row["timestamp_utc"] = p.timestamp_utc;
    row["mode"] = p.mode;
    row["config_hash"] = p.config_hash;
    row["seed"] = p.seed;
    row["git_commit"] = p.git_commit;
    row["dependency_hash"] = p.dependency_hash;
    row["source_tree_hash"] = p.source_tree_hash;
    row["source_script"] = p.source_script;
}

static void write_csv(const fs::path &path, std::vector<Row> rows, const Provenance &p) {
    if (rows.empty()) {
        return;
    }
    fs::create_directories(path.parent_path());
    std::vector<std::string> fields = {
        "env_id", "run_id", "timestamp_utc", "mode", "config_hash", "seed",
        "git_commit", "dependency_hash", "source_tree_hash", "source_script"
    };
    std::set<std::string> seen(fields.begin(), fields.end());
    for (Row &row : rows) {
        add_provenance(row, p);
        for (const auto &[key, _] : row) {
            if (!seen.count(key)) {
                fields.push_back(key);
                seen.insert(key);
            }
        }
    }
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("failed to open CSV for writing: " + path.string());
    }
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i > 0) {
            out << ',';
        }
        out << csv_escape(fields[i]);
    }
    out << '\n';
    for (const Row &row : rows) {
        for (std::size_t i = 0; i < fields.size(); ++i) {
            if (i > 0) {
                out << ',';
            }
            const auto it = row.find(fields[i]);
            if (it != row.end()) {
                out << csv_escape(it->second);
            }
        }
        out << '\n';
    }
    std::cout << "  wrote " << rows.size() << " rows -> " << path << "\n";
}

static Stats compute_stats(std::vector<double> values) {
    Stats s;
    s.n = values.size();
    if (values.empty()) {
        return s;
    }
    std::sort(values.begin(), values.end());
    const double sum = std::accumulate(values.begin(), values.end(), 0.0);
    s.mean = sum / static_cast<double>(values.size());
    s.median = values[values.size() / 2];
    if (values.size() % 2 == 0) {
        s.median = (values[values.size() / 2 - 1] + values[values.size() / 2]) / 2.0;
    }
    const std::size_t p95_idx = std::min(static_cast<std::size_t>(values.size() * 0.95), values.size() - 1);
    s.p95 = values[p95_idx];
    s.min = values.front();
    s.max = values.back();
    if (values.size() > 1) {
        double acc = 0.0;
        for (double v : values) {
            const double d = v - s.mean;
            acc += d * d;
        }
        s.stdev = std::sqrt(acc / static_cast<double>(values.size() - 1));
        const double ci = 1.96 * s.stdev / std::sqrt(static_cast<double>(values.size()));
        s.ci95_low = s.mean - ci;
        s.ci95_high = s.mean + ci;
    } else {
        s.ci95_low = s.mean;
        s.ci95_high = s.mean;
    }
    if (s.mean > 0.0) {
        s.throughput_ops_s = 1000.0 / s.mean;  // ms → ops/s
    }
    return s;
}

static Stats time_op(const std::function<void()> &fn, int runs, int warmup) {
    for (int i = 0; i < warmup; ++i) {
        fn();
    }
    std::vector<double> ms;
    ms.reserve(static_cast<std::size_t>(runs));
    for (int i = 0; i < runs; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        fn();
        const auto t1 = std::chrono::steady_clock::now();
        ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
    }
    return compute_stats(std::move(ms));
}

static void put_stats(Row &row, const std::string &prefix, const Stats &s) {
    row[prefix + "_mean_ms"] = format_double(s.mean);
    row[prefix + "_median_ms"] = format_double(s.median);
    row[prefix + "_p95_ms"] = format_double(s.p95);
    row[prefix + "_stdev_ms"] = format_double(s.stdev);
    row[prefix + "_min_ms"] = format_double(s.min);
    row[prefix + "_max_ms"] = format_double(s.max);
    row[prefix + "_ci95_low_ms"] = format_double(s.ci95_low);
    row[prefix + "_ci95_high_ms"] = format_double(s.ci95_high);
    row[prefix + "_throughput_ops_s"] = format_double(s.throughput_ops_s, 1);
    row[prefix + "_n_runs"] = std::to_string(s.n);
}

static Bytes random_bytes(std::size_t n) {
    Bytes out(n);
    if (n > 0) {
        OQS_randombytes(out.data(), n);
    }
    return out;
}

static Bytes sha256(const Bytes &in) {
    Bytes out(kHashBytes);
    unsigned int out_len = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &out_len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("EVP_Digest(SHA256) failed");
    }
    out.resize(out_len);
    return out;
}

static Bytes sha256_concat(const std::vector<Bytes> &parts) {
    EVP_MD_CTX *raw = EVP_MD_CTX_new();
    if (raw == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(raw, EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    for (const Bytes &part : parts) {
        if (!part.empty() && EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }
    Bytes out(kHashBytes);
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) != 1) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    out.resize(out_len);
    return out;
}

static Bytes hmac_sha256(const Bytes &key, const Bytes &msg) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), msg.data(), msg.size(), out.data(), &len) == nullptr) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    out.resize(len);
    return out;
}

static void append_u16(Bytes &out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}

static void append_u32(Bytes &out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}

static void append_u64(Bytes &out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xff));
    }
}

static void append_double(Bytes &out, double v) {
    static_assert(sizeof(double) == sizeof(std::uint64_t), "unexpected double size");
    std::uint64_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    append_u64(out, bits);
}

static void append_bytes_with_u16_len(Bytes &out, const Bytes &b) {
    if (b.size() > 0xffff) {
        throw std::runtime_error("u16 length overflow");
    }
    append_u16(out, static_cast<std::uint16_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
}

static void append_string_with_u16_len(Bytes &out, const std::string &s) {
    if (s.size() > 0xffff) {
        throw std::runtime_error("u16 string length overflow");
    }
    append_u16(out, static_cast<std::uint16_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

static Bytes str_bytes(const std::string &s) {
    return Bytes(s.begin(), s.end());
}

// Injective stream identity: length-prefix each UTF-8 component so that
// (client_id, topic) never collides.  std::string::size() is the byte length,
// so this is byte-identical to Python stream_identity.canonical_stream_id().
static std::string canonical_stream_id(const std::string &client_id,
                                       const std::string &topic) {
    return std::to_string(client_id.size()) + ":" + client_id +
           std::to_string(topic.size()) + ":" + topic;
}

struct OqsKem {
    explicit OqsKem(std::string alg_name) : alg(std::move(alg_name)), kem(OQS_KEM_new(alg.c_str())) {
        if (kem == nullptr) {
            throw std::runtime_error("OQS KEM not available: " + alg);
        }
    }
    ~OqsKem() {
        OQS_KEM_free(kem);
    }
    OqsKem(const OqsKem &) = delete;
    OqsKem &operator=(const OqsKem &) = delete;

    std::pair<Bytes, Bytes> keypair() const {
        Bytes pk(kem->length_public_key);
        Bytes sk(kem->length_secret_key);
        if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_keypair failed: " + alg);
        }
        return {std::move(pk), std::move(sk)};
    }

    std::pair<Bytes, Bytes> encaps(const Bytes &pk) const {
        Bytes ct(kem->length_ciphertext);
        Bytes ss(kem->length_shared_secret);
        if (OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_encaps failed: " + alg);
        }
        return {std::move(ct), std::move(ss)};
    }

    Bytes decaps(const Bytes &ct, const Bytes &sk) const {
        Bytes ss(kem->length_shared_secret);
        if (OQS_KEM_decaps(kem, ss.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_decaps failed: " + alg);
        }
        return ss;
    }

    std::string alg;
    OQS_KEM *kem = nullptr;
};

struct OqsSig {
    explicit OqsSig(std::string alg_name) : alg(std::move(alg_name)), sig(OQS_SIG_new(alg.c_str())) {
        if (sig == nullptr) {
            throw std::runtime_error("OQS SIG not available: " + alg);
        }
    }
    ~OqsSig() {
        OQS_SIG_free(sig);
    }
    OqsSig(const OqsSig &) = delete;
    OqsSig &operator=(const OqsSig &) = delete;

    std::pair<Bytes, Bytes> keypair() const {
        Bytes pk(sig->length_public_key);
        Bytes sk(sig->length_secret_key);
        if (OQS_SIG_keypair(sig, pk.data(), sk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_SIG_keypair failed: " + alg);
        }
        return {std::move(pk), std::move(sk)};
    }

    Bytes sign(const Bytes &msg, const Bytes &sk) const {
        Bytes signature(sig->length_signature);
        std::size_t sig_len = 0;
        if (OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), sk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_SIG_sign failed: " + alg);
        }
        signature.resize(sig_len);
        return signature;
    }

    bool verify(const Bytes &msg, const Bytes &signature, const Bytes &pk) const {
        return OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), signature.size(), pk.data()) == OQS_SUCCESS;
    }

    std::string alg;
    OQS_SIG *sig = nullptr;
};

struct OqsSigKey {
    OqsSigKey() = default;
    OqsSigKey(OqsSig &scheme, std::string id_value = "") : id(std::move(id_value)) {
        auto [new_pk, new_sk] = scheme.keypair();
        pk = std::move(new_pk);
        sk = std::move(new_sk);
    }
    std::string id;
    Bytes pk;
    Bytes sk;
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY *p) const {
        EVP_PKEY_free(p);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

static EvpPkeyPtr openssl_generate_key(int type) {
    EVP_PKEY_CTX *raw = EVP_PKEY_CTX_new_id(type, nullptr);
    if (raw == nullptr) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw, EVP_PKEY_CTX_free);
    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }
    EVP_PKEY *key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &key) != 1) {
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    return EvpPkeyPtr(key);
}

static Bytes openssl_raw_public(EVP_PKEY *key) {
    std::size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &len) != 1) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key length failed");
    }
    Bytes out(len);
    if (EVP_PKEY_get_raw_public_key(key, out.data(), &len) != 1) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    out.resize(len);
    return out;
}

static Bytes openssl_raw_private(EVP_PKEY *key) {
    std::size_t len = 0;
    if (EVP_PKEY_get_raw_private_key(key, nullptr, &len) != 1) {
        throw std::runtime_error("EVP_PKEY_get_raw_private_key length failed");
    }
    Bytes out(len);
    if (EVP_PKEY_get_raw_private_key(key, out.data(), &len) != 1) {
        throw std::runtime_error("EVP_PKEY_get_raw_private_key failed");
    }
    out.resize(len);
    return out;
}

static Bytes openssl_ed25519_sign(EVP_PKEY *key, const Bytes &msg) {
    EVP_MD_CTX *raw = EVP_MD_CTX_new();
    if (raw == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(raw, EVP_MD_CTX_free);
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1) {
        throw std::runtime_error("EVP_DigestSignInit Ed25519 failed");
    }
    std::size_t sig_len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, msg.data(), msg.size()) != 1) {
        throw std::runtime_error("EVP_DigestSign length failed");
    }
    Bytes sig(sig_len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len, msg.data(), msg.size()) != 1) {
        throw std::runtime_error("EVP_DigestSign failed");
    }
    sig.resize(sig_len);
    return sig;
}

static bool openssl_ed25519_verify(EVP_PKEY *key, const Bytes &msg, const Bytes &sig) {
    EVP_MD_CTX *raw = EVP_MD_CTX_new();
    if (raw == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(raw, EVP_MD_CTX_free);
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1) {
        throw std::runtime_error("EVP_DigestVerifyInit Ed25519 failed");
    }
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
}

static Bytes openssl_x25519_derive(EVP_PKEY *priv, EVP_PKEY *peer_pub) {
    EVP_PKEY_CTX *raw = EVP_PKEY_CTX_new(priv, nullptr);
    if (raw == nullptr) {
        throw std::runtime_error("EVP_PKEY_CTX_new derive failed");
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw, EVP_PKEY_CTX_free);
    if (EVP_PKEY_derive_init(ctx.get()) != 1) {
        throw std::runtime_error("EVP_PKEY_derive_init failed");
    }
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer_pub) != 1) {
        throw std::runtime_error("EVP_PKEY_derive_set_peer failed");
    }
    std::size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) {
        throw std::runtime_error("EVP_PKEY_derive length failed");
    }
    Bytes secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) != 1) {
        throw std::runtime_error("EVP_PKEY_derive failed");
    }
    secret.resize(len);
    return secret;
}

struct Record {
    std::uint32_t seq = 0;
    double ts = 0.0;
    std::string topic;
    Bytes payload;

    Bytes serialize() const {
        if (!std::isfinite(ts)) {
            throw std::runtime_error("record timestamp must be finite");
        }
        Bytes out;
        append_u32(out, seq);
        append_double(out, ts);
        append_string_with_u16_len(out, topic);
        append_u32(out, static_cast<std::uint32_t>(payload.size()));
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }
};

struct ProofStep {
    Bytes sibling;
    bool current_is_left = true;
};

using Proof = std::vector<ProofStep>;

struct MerkleTree {
    std::vector<Bytes> leaves;
    std::vector<Bytes> records;
    std::vector<std::vector<Bytes>> levels;

    void append(const Bytes &record) {
        leaves.push_back(sha256_concat({Bytes{0x00}, record}));
        records.push_back(record);
    }

    Bytes build() {
        if (leaves.empty()) {
            return {};
        }
        levels.clear();
        levels.push_back(leaves);
        std::vector<Bytes> current = leaves;
        while (current.size() > 1) {
            if (current.size() % 2 == 1) {
                current.push_back(current.back());
            }
            std::vector<Bytes> next;
            next.reserve(current.size() / 2);
            for (std::size_t i = 0; i < current.size(); i += 2) {
                next.push_back(sha256_concat({Bytes{0x01}, current[i], current[i + 1]}));
            }
            levels.push_back(next);
            current = std::move(next);
        }
        return levels.back().front();
    }

    Proof proof(std::size_t idx) const {
        if (idx >= leaves.size()) {
            throw std::runtime_error("Merkle proof index out of range");
        }
        Proof out;
        std::size_t pos = idx;
        for (std::size_t level = 0; level + 1 < levels.size(); ++level) {
            std::size_t sibling = pos ^ 1U;
            if (sibling >= levels[level].size()) {
                sibling = pos;
            }
            out.push_back({levels[level][sibling], pos % 2 == 0});
            pos /= 2;
        }
        return out;
    }

    static bool verify(const Bytes &record, const Proof &proof, const Bytes &root) {
        Bytes current = sha256_concat({Bytes{0x00}, record});
        for (const ProofStep &step : proof) {
            if (step.current_is_left) {
                current = sha256_concat({Bytes{0x01}, current, step.sibling});
            } else {
                current = sha256_concat({Bytes{0x01}, step.sibling, current});
            }
        }
        return current == root;
    }
};

struct HashChain {
    Bytes seed;
    std::vector<Bytes> values;
    std::vector<Bytes> records;

    explicit HashChain(Bytes seed_value) : seed(std::move(seed_value)) {
        values.push_back(sha256(seed));
    }

    void append(const Bytes &record) {
        values.push_back(sha256_concat({values.back(), record}));
        records.push_back(record);
    }

    const Bytes &head() const {
        return values.back();
    }
};

struct Checkpoint {
    std::string client_id;
    std::string topic;
    std::uint32_t epoch = 0;
    std::uint32_t seq_start = 0;
    std::uint32_t seq_end = 0;
    Bytes prev_anchor;
    Bytes end_anchor;
    double ts_ckpt = 0.0;

    Bytes serialize() const {
        if (!std::isfinite(ts_ckpt) || seq_end < seq_start) {
            throw std::runtime_error("invalid checkpoint range or timestamp");
        }
        Bytes out;
        out.insert(out.end(), kCheckpointSigningDomain,
                   kCheckpointSigningDomain + std::strlen(kCheckpointSigningDomain));
        append_string_with_u16_len(out, client_id);
        append_string_with_u16_len(out, topic);
        append_u32(out, epoch);
        append_u32(out, seq_start);
        append_u32(out, seq_end);
        append_bytes_with_u16_len(out, prev_anchor);
        append_bytes_with_u16_len(out, end_anchor);
        append_double(out, ts_ckpt);
        return out;
    }
};

struct WitnessReceipt {
    std::string witness_id;
    std::string stream_id;
    std::uint32_t checkpoint_epoch = 0;
    std::uint32_t seq_start = 0;
    std::uint32_t seq_end = 0;
    Bytes prev_witnessed_anchor;
    Bytes checkpoint_anchor;
    double ts_witness = 0.0;
    Bytes signature;
    Bytes public_key;

    Bytes body() const {
        if (!std::isfinite(ts_witness) || seq_end < seq_start) {
            throw std::runtime_error("invalid witness range or timestamp");
        }
        Bytes out;
        out.insert(out.end(), kWitnessSigningDomain,
                   kWitnessSigningDomain + std::strlen(kWitnessSigningDomain));
        append_string_with_u16_len(out, witness_id);
        append_string_with_u16_len(out, stream_id);
        append_u32(out, checkpoint_epoch);
        append_u32(out, seq_start);
        append_u32(out, seq_end);
        append_bytes_with_u16_len(out, prev_witnessed_anchor);
        append_bytes_with_u16_len(out, checkpoint_anchor);
        append_double(out, ts_witness);
        return out;
    }
};

struct Evidence {
    std::string arm;
    Checkpoint checkpoint;
    Bytes signature;
    Bytes public_key;
    std::vector<Bytes> records;
    std::vector<Proof> merkle_proofs;
    Bytes chain_seed;
    std::vector<Bytes> chain_values;
    std::vector<WitnessReceipt> witness_receipts;
};

struct PublisherTrust {
    std::string client_id;
    std::string topic;
    Bytes public_key;
};

using WitnessRegistry = std::map<std::string, Bytes>;

static PublisherTrust publisher_trust(const OqsSigKey &publisher, const std::string &topic) {
    return {kClientId, topic, publisher.pk};
}

static WitnessRegistry witness_registry(const std::vector<OqsSigKey> &witnesses) {
    WitnessRegistry registry;
    for (const OqsSigKey &witness : witnesses) {
        registry.emplace(witness.id, witness.pk);
    }
    return registry;
}

static bool publisher_is_trusted(const Evidence &ev, const PublisherTrust &trust) {
    return ev.checkpoint.client_id == trust.client_id &&
        ev.checkpoint.topic == trust.topic &&
        ev.public_key == trust.public_key;
}

struct ComponentSizes {
    std::size_t checkpoint_metadata_bytes = 0;
    std::size_t signature_bytes = 0;
    std::size_t public_key_bytes = 0;
    std::size_t records_raw_bytes = 0;
    std::size_t merkle_proofs_raw_bytes = 0;
    std::size_t chain_seed_bytes = 0;
    std::size_t chain_values_raw_bytes = 0;
    std::size_t witness_receipts_raw_bytes = 0;
    std::size_t full_evidence_raw_bytes = 0;
};

static ComponentSizes component_sizes(const Evidence &ev) {
    ComponentSizes s;
    s.checkpoint_metadata_bytes = ev.checkpoint.serialize().size();
    s.signature_bytes = ev.signature.size();
    s.public_key_bytes = ev.public_key.size();
    for (const Bytes &r : ev.records) {
        s.records_raw_bytes += r.size();
    }
    for (const Proof &proof : ev.merkle_proofs) {
        for (const ProofStep &step : proof) {
            s.merkle_proofs_raw_bytes += step.sibling.size() + 1;
        }
    }
    s.chain_seed_bytes = ev.chain_seed.size();
    for (const Bytes &v : ev.chain_values) {
        s.chain_values_raw_bytes += v.size();
    }
    for (const WitnessReceipt &r : ev.witness_receipts) {
        s.witness_receipts_raw_bytes += r.body().size() + r.signature.size() + r.public_key.size();
    }
    s.full_evidence_raw_bytes =
        s.checkpoint_metadata_bytes + s.signature_bytes + s.public_key_bytes +
        s.records_raw_bytes + s.merkle_proofs_raw_bytes + s.chain_seed_bytes +
        s.chain_values_raw_bytes + s.witness_receipts_raw_bytes;
    return s;
}

static std::string topic_for(const std::string &arm) {
    std::string lower = arm;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return "aapa/" + lower + "/telemetry";
}

static Bytes payload_pattern(std::size_t size, std::uint32_t seq) {
    Bytes out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>((seq + i) & 0xff);
    }
    return out;
}

static std::vector<Record> make_records(std::size_t n, const std::string &topic, std::size_t payload_bytes, std::uint32_t seq_start) {
    std::vector<Record> records;
    records.reserve(n);
    const double base_ts = now_unix_double();
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint32_t seq = seq_start + static_cast<std::uint32_t>(i);
        records.push_back({seq, base_ts + static_cast<double>(i) / 1000.0, topic, payload_pattern(payload_bytes, seq)});
    }
    return records;
}

static Checkpoint make_checkpoint(
    const std::string &topic,
    std::uint32_t epoch,
    std::uint32_t seq_start,
    std::uint32_t seq_end,
    const Bytes &prev_anchor,
    const Bytes &end_anchor,
    double ts = now_unix_double()) {
    return {kClientId, topic, epoch, seq_start, seq_end, prev_anchor, end_anchor, ts};
}

static Bytes derive_hmac_key(const Bytes &secret) {
    Bytes info = str_bytes("hmac-key");
    return sha256_concat({secret, info});
}

static Bytes make_hmac_key_once() {
    OqsKem kem(kKemMain);
    auto [sub_pk, sub_sk] = kem.keypair();
    auto [ct, shared_pub] = kem.encaps(sub_pk);
    Bytes shared_sub = kem.decaps(ct, sub_sk);
    if (shared_pub != shared_sub) {
        throw std::runtime_error("ML-KEM shared secret mismatch");
    }
    return derive_hmac_key(shared_pub);
}

static WitnessReceipt make_witness_receipt(
    OqsSig &scheme,
    const OqsSigKey &witness,
    const Checkpoint &ckpt,
    double ts_witness = now_unix_double()) {
    const std::string stream_id = canonical_stream_id(ckpt.client_id, ckpt.topic);
    WitnessReceipt receipt;
    receipt.witness_id = witness.id;
    receipt.stream_id = stream_id;
    receipt.checkpoint_epoch = ckpt.epoch;
    receipt.seq_start = ckpt.seq_start;
    receipt.seq_end = ckpt.seq_end;
    receipt.prev_witnessed_anchor = ckpt.prev_anchor;
    receipt.checkpoint_anchor = ckpt.end_anchor;
    receipt.ts_witness = ts_witness;
    receipt.public_key = witness.pk;
    receipt.signature = scheme.sign(receipt.body(), witness.sk);
    return receipt;
}

static Evidence make_a1_message_evidence(
    OqsSig &scheme,
    const OqsSigKey &publisher,
    const Record &rec,
    const Bytes &prev_anchor,
    std::uint32_t epoch) {
    const Bytes raw = rec.serialize();
    const Bytes anchor = sha256(raw);
    Checkpoint ckpt = make_checkpoint(rec.topic, epoch, rec.seq, rec.seq, prev_anchor, anchor, rec.ts);
    Evidence ev;
    ev.arm = "A1";
    ev.checkpoint = std::move(ckpt);
    ev.signature = scheme.sign(raw, publisher.sk);
    ev.public_key = publisher.pk;
    ev.records = {raw};
    return ev;
}

static Evidence make_a3_evidence(
    OqsSig &scheme,
    const OqsSigKey &publisher,
    const Bytes &hmac_key,
    const std::string &topic,
    std::size_t n,
    std::size_t payload_bytes,
    const Bytes &prev_anchor,
    std::uint32_t seq_start,
    std::uint32_t epoch) {
    HashChain chain(random_bytes(kHashBytes));
    std::vector<Record> records = make_records(n, topic, payload_bytes, seq_start);
    for (const Record &rec : records) {
        const Bytes raw = rec.serialize();
        (void) hmac_sha256(hmac_key, raw);
        chain.append(raw);
    }
    Checkpoint ckpt = make_checkpoint(topic, epoch, seq_start, seq_start + static_cast<std::uint32_t>(n) - 1, prev_anchor, chain.head());
    Evidence ev;
    ev.arm = "A3";
    ev.checkpoint = std::move(ckpt);
    ev.signature = scheme.sign(ev.checkpoint.serialize(), publisher.sk);
    ev.public_key = publisher.pk;
    ev.records = chain.records;
    ev.chain_seed = chain.seed;
    ev.chain_values = chain.values;
    return ev;
}

static Evidence make_a4_evidence(
    OqsSig &scheme,
    const OqsSigKey &publisher,
    const Bytes &hmac_key,
    const std::string &topic,
    std::size_t n,
    std::size_t payload_bytes,
    const Bytes &prev_anchor,
    std::uint32_t seq_start,
    std::uint32_t epoch) {
    MerkleTree tree;
    std::vector<Record> records = make_records(n, topic, payload_bytes, seq_start);
    for (const Record &rec : records) {
        const Bytes raw = rec.serialize();
        (void) hmac_sha256(hmac_key, raw);
        tree.append(raw);
    }
    const Bytes root = tree.build();
    Checkpoint ckpt = make_checkpoint(topic, epoch, seq_start, seq_start + static_cast<std::uint32_t>(n) - 1, prev_anchor, root);
    Evidence ev;
    ev.arm = "A4";
    ev.checkpoint = std::move(ckpt);
    ev.signature = scheme.sign(ev.checkpoint.serialize(), publisher.sk);
    ev.public_key = publisher.pk;
    ev.records = tree.records;
    ev.merkle_proofs.reserve(tree.records.size());
    for (std::size_t i = 0; i < tree.records.size(); ++i) {
        ev.merkle_proofs.push_back(tree.proof(i));
    }
    return ev;
}

static Evidence make_a6_evidence(
    OqsSig &scheme,
    const OqsSigKey &publisher,
    const std::vector<OqsSigKey> &witnesses,
    const Bytes &hmac_key,
    const std::string &topic,
    std::size_t n,
    std::size_t payload_bytes,
    const Bytes &prev_anchor,
    std::uint32_t seq_start,
    std::uint32_t epoch,
    double witness_ts = now_unix_double()) {
    Evidence ev = make_a4_evidence(scheme, publisher, hmac_key, topic, n, payload_bytes, prev_anchor, seq_start, epoch);
    ev.arm = "A6";
    ev.witness_receipts.reserve(witnesses.size());
    for (const OqsSigKey &w : witnesses) {
        ev.witness_receipts.push_back(make_witness_receipt(scheme, w, ev.checkpoint, witness_ts));
    }
    return ev;
}

[[maybe_unused]] static bool verify_a1(
    const Evidence &ev,
    OqsSig &scheme,
    const PublisherTrust &trust) {
    if (ev.records.size() != 1) {
        return false;
    }
    if (!publisher_is_trusted(ev, trust)) {
        return false;
    }
    const bool sig_ok = scheme.verify(ev.records.front(), ev.signature, trust.public_key);
    const bool hash_ok = sha256(ev.records.front()) == ev.checkpoint.end_anchor;
    return sig_ok && hash_ok;
}

static bool verify_a3(
    const Evidence &ev,
    OqsSig &scheme,
    bool include_signature,
    const PublisherTrust &trust) {
    if (!publisher_is_trusted(ev, trust)) {
        return false;
    }
    if (include_signature && !scheme.verify(ev.checkpoint.serialize(), ev.signature, trust.public_key)) {
        return false;
    }
    if (ev.chain_seed.empty() || ev.chain_values.empty()) {
        return false;
    }
    HashChain chain(ev.chain_seed);
    for (const Bytes &record : ev.records) {
        chain.append(record);
    }
    return chain.head() == ev.checkpoint.end_anchor && chain.values == ev.chain_values;
}

static bool verify_a4(
    const Evidence &ev,
    OqsSig &scheme,
    std::size_t k,
    bool include_signature,
    const PublisherTrust &trust) {
    if (!publisher_is_trusted(ev, trust)) {
        return false;
    }
    if (include_signature && !scheme.verify(ev.checkpoint.serialize(), ev.signature, trust.public_key)) {
        return false;
    }
    if (k > ev.records.size() || k > ev.merkle_proofs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < k; ++i) {
        if (!MerkleTree::verify(ev.records[i], ev.merkle_proofs[i], ev.checkpoint.end_anchor)) {
            return false;
        }
    }
    return true;
}

struct WitnessPolicy {
    std::size_t min_receipts = 1;
    std::optional<double> freshness_window_s;
    std::optional<Bytes> latest_anchor;
    double now = now_unix_double();
};

static bool verify_witness_receipts(
    const Evidence &ev,
    OqsSig &scheme,
    const WitnessPolicy &policy,
    const WitnessRegistry &registry) {
    if (policy.latest_anchor.has_value() && ev.checkpoint.end_anchor != policy.latest_anchor.value()) {
        return false;
    }
    const std::string stream_id = canonical_stream_id(ev.checkpoint.client_id, ev.checkpoint.topic);
    std::size_t valid = 0;
    std::set<std::string> counted_ids;
    std::set<Bytes> counted_keys;
    for (const WitnessReceipt &r : ev.witness_receipts) {
        const auto trusted = registry.find(r.witness_id);
        if (trusted == registry.end() || r.public_key != trusted->second) {
            continue;
        }
        if (counted_ids.count(r.witness_id) || counted_keys.count(trusted->second)) {
            continue;
        }
        const bool fields_match =
            r.stream_id == stream_id &&
            r.checkpoint_epoch == ev.checkpoint.epoch &&
            r.seq_start == ev.checkpoint.seq_start &&
            r.seq_end == ev.checkpoint.seq_end &&
            r.prev_witnessed_anchor == ev.checkpoint.prev_anchor &&
            r.checkpoint_anchor == ev.checkpoint.end_anchor;
        const double age = policy.now - r.ts_witness;
        const bool not_future = age >= 0.0;
        const bool fresh = not_future && (!policy.freshness_window_s.has_value() ||
            age <= policy.freshness_window_s.value());
        const bool sig_ok = scheme.verify(r.body(), r.signature, trusted->second);
        if (fields_match && fresh && sig_ok) {
            ++valid;
            counted_ids.insert(r.witness_id);
            counted_keys.insert(trusted->second);
        }
    }
    return valid >= policy.min_receipts;
}

static bool verify_a6(
    const Evidence &ev,
    OqsSig &scheme,
    std::size_t k_disclosed,
    const WitnessPolicy &policy,
    const PublisherTrust &publisher,
    const WitnessRegistry &witnesses) {
    return verify_a4(ev, scheme, k_disclosed, true, publisher) &&
        verify_witness_receipts(ev, scheme, policy, witnesses);
}

static std::size_t record_overhead(const std::string &topic) {
    return 4 + 8 + 2 + topic.size() + 4;
}

static std::size_t mqtt_framing(
    const std::string &topic,
    int qos,
    std::size_t application_payload_bytes) {
    const std::size_t variable_header = 2 + topic.size() + (qos > 0 ? 2 : 0);
    std::size_t remaining_length = variable_header + application_payload_bytes;
    std::size_t remaining_len_bytes = 1;
    while (remaining_length >= 128) {
        remaining_length /= 128;
        ++remaining_len_bytes;
    }
    return 1 + remaining_len_bytes + variable_header;
}

static std::size_t mac_wire_envelope_bytes(std::size_t record_bytes) {
    // Must match Python WireEnvelope v1: 30-byte fixed metadata header,
    // algorithm/key/session identifiers, 2-byte tag length, and HMAC-SHA256.
    constexpr std::size_t header = 30;
    constexpr std::size_t algorithm = 11;  // "HMAC-SHA256"
    constexpr std::size_t key_id = 36;      // "mac-" + 32 hex chars
    constexpr std::size_t session_id = 40;  // "session-" + 32 hex chars
    constexpr std::size_t tag_length = 2;
    constexpr std::size_t tag = 32;
    return header + algorithm + key_id + session_id + record_bytes + tag_length + tag;
}

static std::vector<std::string> kem_algs(const Options &opt) {
    (void) opt;
    // The study characterizes an audit architecture, not algorithm diversity.
    return {OQS_KEM_alg_ml_kem_768};
}

static std::vector<std::string> sig_algs(const Options &opt) {
    (void) opt;
    // ML-DSA-65 is the formal arm. SLH-DSA remains a small optional coverage
    // point and is not crossed with the MQTT/QoS experiment matrix.
    return {OQS_SIG_alg_ml_dsa_65, OQS_SIG_alg_slh_dsa_pure_sha2_128f};
}

static std::vector<std::size_t> batch_sizes(const Options &opt) {
    if (opt.mode == "quick") {
        return {10, 100};
    }
    return {1, 10, 50, 100, 500, 1000};
}

static std::vector<std::size_t> k_values(const Options &opt) {
    if (opt.mode == "quick") {
        return {1, 10};
    }
    return {1, 5, 10, 50, 100};
}

static std::vector<std::size_t> witness_counts(const Options &opt) {
    if (opt.mode == "quick") {
        return {1, 3};
    }
    return {1, 3, 5, 7};
}

static std::vector<Row> bench_kems(const Options &opt) {
    std::vector<Row> rows;
    for (const std::string &alg : kem_algs(opt)) {
        if (!OQS_KEM_alg_is_enabled(alg.c_str())) {
            continue;
        }
        std::cout << "  KEM " << alg << "\n";
        OqsKem kem(alg);
        Row row;
        row["primitive"] = alg;
        row["category"] = "KEM";
        row["n_runs"] = std::to_string(opt.runs);

        Bytes pk;
        Bytes sk;
        auto keygen_stats = time_op([&]() {
            auto kp = kem.keypair();
            pk = std::move(kp.first);
            sk = std::move(kp.second);
        }, opt.runs, opt.warmup);
        put_stats(row, "keygen", keygen_stats);

        auto kp = kem.keypair();
        pk = kp.first;
        sk = kp.second;
        Bytes ct;
        Bytes ss;
        auto encaps_stats = time_op([&]() {
            auto enc = kem.encaps(pk);
            ct = std::move(enc.first);
            ss = std::move(enc.second);
        }, opt.runs, opt.warmup);
        put_stats(row, "encaps", encaps_stats);

        auto enc = kem.encaps(pk);
        ct = enc.first;
        auto decaps_stats = time_op([&]() {
            Bytes got = kem.decaps(ct, sk);
            if (got.size() != kem.kem->length_shared_secret) {
                throw std::runtime_error("bad decaps size");
            }
        }, opt.runs, opt.warmup);
        put_stats(row, "decaps", decaps_stats);
        rows.push_back(std::move(row));
    }
    return rows;
}

static std::vector<Row> bench_sigs(const Options &opt) {
    std::vector<Row> rows;
    const Bytes msg = str_bytes("Benchmark message for PQC signature testing.");
    for (const std::string &alg : sig_algs(opt)) {
        if (!OQS_SIG_alg_is_enabled(alg.c_str())) {
            continue;
        }
        std::cout << "  SIG " << alg << "\n";
        OqsSig scheme(alg);
        Row row;
        row["primitive"] = alg;
        row["category"] = "SIG";
        row["n_runs"] = std::to_string(opt.runs);

        Bytes pk;
        Bytes sk;
        auto keygen_stats = time_op([&]() {
            auto kp = scheme.keypair();
            pk = std::move(kp.first);
            sk = std::move(kp.second);
        }, opt.runs, opt.warmup);
        put_stats(row, "keygen", keygen_stats);

        auto kp = scheme.keypair();
        pk = kp.first;
        sk = kp.second;
        Bytes signature;
        auto sign_stats = time_op([&]() {
            signature = scheme.sign(msg, sk);
        }, opt.runs, opt.warmup);
        put_stats(row, "sign", sign_stats);

        signature = scheme.sign(msg, sk);
        auto verify_stats = time_op([&]() {
            if (!scheme.verify(msg, signature, pk)) {
                throw std::runtime_error("signature verify failed for " + alg);
            }
        }, opt.runs, opt.warmup);
        put_stats(row, "verify", verify_stats);
        rows.push_back(std::move(row));
    }
    return rows;
}

static std::vector<Row> bench_classical(const Options &opt) {
    std::vector<Row> rows;
    const Bytes msg = str_bytes("Benchmark message for classical crypto.");

    {
        Row row;
        row["primitive"] = "Ed25519";
        row["category"] = "SIG";
        auto key = openssl_generate_key(EVP_PKEY_ED25519);
        Bytes signature = openssl_ed25519_sign(key.get(), msg);

        auto keygen_stats = time_op([&]() {
            auto k = openssl_generate_key(EVP_PKEY_ED25519);
            (void) openssl_raw_public(k.get());
        }, opt.runs, opt.warmup);
        put_stats(row, "keygen", keygen_stats);

        auto sign_stats = time_op([&]() {
            signature = openssl_ed25519_sign(key.get(), msg);
        }, opt.runs, opt.warmup);
        put_stats(row, "sign", sign_stats);

        auto verify_stats = time_op([&]() {
            if (!openssl_ed25519_verify(key.get(), msg, signature)) {
                throw std::runtime_error("Ed25519 verify failed");
            }
        }, opt.runs, opt.warmup);
        put_stats(row, "verify", verify_stats);
        rows.push_back(std::move(row));
    }

    {
        Row row;
        row["primitive"] = "X25519";
        row["category"] = "KEM";
        auto alice = openssl_generate_key(EVP_PKEY_X25519);
        auto bob = openssl_generate_key(EVP_PKEY_X25519);

        auto keygen_stats = time_op([&]() {
            auto k = openssl_generate_key(EVP_PKEY_X25519);
            (void) openssl_raw_public(k.get());
        }, opt.runs, opt.warmup);
        put_stats(row, "keygen", keygen_stats);

        auto encaps_stats = time_op([&]() {
            Bytes ss = openssl_x25519_derive(bob.get(), alice.get());
            if (ss.empty()) {
                throw std::runtime_error("X25519 derive failed");
            }
        }, opt.runs, opt.warmup);
        put_stats(row, "encaps", encaps_stats);

        auto decaps_stats = time_op([&]() {
            Bytes ss = openssl_x25519_derive(alice.get(), bob.get());
            if (ss.empty()) {
                throw std::runtime_error("X25519 derive failed");
            }
        }, opt.runs, opt.warmup);
        put_stats(row, "decaps", decaps_stats);
        rows.push_back(std::move(row));
    }

    return rows;
}

static std::vector<Row> object_sizes(const Options &opt) {
    std::vector<Row> rows;
    for (const std::string &alg : kem_algs(opt)) {
        if (!OQS_KEM_alg_is_enabled(alg.c_str())) {
            continue;
        }
        OqsKem kem(alg);
        auto [pk, sk] = kem.keypair();
        auto [ct, ss] = kem.encaps(pk);
        Row row;
        row["primitive"] = alg;
        row["category"] = "KEM";
        row["pk_bytes"] = std::to_string(pk.size());
        row["sk_bytes"] = std::to_string(sk.size());
        row["ct_bytes"] = std::to_string(ct.size());
        row["ss_bytes"] = std::to_string(ss.size());
        rows.push_back(std::move(row));
    }
    for (const std::string &alg : sig_algs(opt)) {
        if (!OQS_SIG_alg_is_enabled(alg.c_str())) {
            continue;
        }
        OqsSig scheme(alg);
        auto [pk, sk] = scheme.keypair();
        Bytes sig = scheme.sign(str_bytes("size test"), sk);
        Row row;
        row["primitive"] = alg;
        row["category"] = "SIG";
        row["pk_bytes"] = std::to_string(pk.size());
        row["sk_bytes"] = std::to_string(sk.size());
        row["sig_bytes"] = std::to_string(sig.size());
        rows.push_back(std::move(row));
    }

    auto ed = openssl_generate_key(EVP_PKEY_ED25519);
    Row ed_row;
    ed_row["primitive"] = "Ed25519";
    ed_row["category"] = "SIG";
    ed_row["pk_bytes"] = std::to_string(openssl_raw_public(ed.get()).size());
    ed_row["sk_bytes"] = std::to_string(openssl_raw_private(ed.get()).size());
    ed_row["sig_bytes"] = std::to_string(openssl_ed25519_sign(ed.get(), str_bytes("size test")).size());
    rows.push_back(std::move(ed_row));

    auto x = openssl_generate_key(EVP_PKEY_X25519);
    Row x_row;
    x_row["primitive"] = "X25519";
    x_row["category"] = "KEM";
    x_row["pk_bytes"] = std::to_string(openssl_raw_public(x.get()).size());
    x_row["sk_bytes"] = std::to_string(openssl_raw_private(x.get()).size());
    x_row["ct_bytes"] = "32";
    x_row["ss_bytes"] = "32";
    rows.push_back(std::move(x_row));

    return rows;
}

static void add_component_fields(Row &row, const ComponentSizes &s) {
    row["checkpoint_metadata_bytes"] = std::to_string(s.checkpoint_metadata_bytes);
    row["signature_bytes"] = std::to_string(s.signature_bytes);
    row["public_key_bytes"] = std::to_string(s.public_key_bytes);
    row["records_raw_bytes"] = std::to_string(s.records_raw_bytes);
    row["merkle_proofs_raw_bytes"] = std::to_string(s.merkle_proofs_raw_bytes);
    row["chain_seed_bytes"] = std::to_string(s.chain_seed_bytes);
    row["chain_values_raw_bytes"] = std::to_string(s.chain_values_raw_bytes);
    row["witness_receipts_raw_bytes"] = std::to_string(s.witness_receipts_raw_bytes);
    row["full_evidence_raw_bytes"] = std::to_string(s.full_evidence_raw_bytes);
}

static std::vector<Row> run_e4_amortized_cpp(const Options &opt) {
    std::cout << "E4 C++ audit-layer amortized overhead\n";
    std::vector<Row> rows;
    OqsSig sig_scheme(kSigMain);
    OqsSigKey publisher(sig_scheme, "publisher");
    const Bytes hmac_key = make_hmac_key_once();

    const std::vector<std::string> arms = {"A1", "A2", "A3", "A4", "A6"};
    for (const std::string &arm : arms) {
        for (std::size_t requested_n : batch_sizes(opt)) {
            const std::size_t effective_n = (arm == "A1" || arm == "A2") ? 1 : requested_n;
            const std::size_t n_msgs = std::max<std::size_t>(effective_n * 3, 100);
            const std::string topic = topic_for(arm);
            const std::size_t record_bytes = opt.payload_bytes + record_overhead(topic);
            const std::size_t wire_payload_bytes = mac_wire_envelope_bytes(record_bytes);
            const std::size_t online_record_wire = n_msgs * (
                wire_payload_bytes + mqtt_framing(topic, 0, wire_payload_bytes));
            std::vector<std::size_t> witnesses = arm == "A6" ? witness_counts(opt) : std::vector<std::size_t>{0};

            for (std::size_t m : witnesses) {
                std::vector<OqsSigKey> witness_keys;
                for (std::size_t i = 0; i < m; ++i) {
                    witness_keys.emplace_back(sig_scheme, "witness-" + std::to_string(i + 1));
                }

                ComponentSizes total;
                Bytes prev(kHashBytes, 0);
                std::uint32_t seq = 1;
                std::uint32_t epoch = 0;

                if (arm == "A2") {
                    // No transferable checkpoint evidence.
                } else if (arm == "A1") {
                    std::vector<Record> records = make_records(n_msgs, topic, opt.payload_bytes, seq);
                    for (const Record &rec : records) {
                        Evidence ev = make_a1_message_evidence(sig_scheme, publisher, rec, prev, epoch++);
                        prev = ev.checkpoint.end_anchor;
                        ComponentSizes s = component_sizes(ev);
                        total.checkpoint_metadata_bytes += s.checkpoint_metadata_bytes;
                        total.signature_bytes += s.signature_bytes;
                        total.public_key_bytes += s.public_key_bytes;
                        total.records_raw_bytes += s.records_raw_bytes;
                        total.full_evidence_raw_bytes += s.full_evidence_raw_bytes;
                    }
                } else {
                    while (seq <= n_msgs) {
                        const std::size_t remaining = n_msgs - seq + 1;
                        const std::size_t batch = std::min(effective_n, remaining);
                        Evidence ev;
                        if (arm == "A3") {
                            ev = make_a3_evidence(sig_scheme, publisher, hmac_key, topic, batch, opt.payload_bytes, prev, seq, epoch);
                        } else if (arm == "A4") {
                            ev = make_a4_evidence(sig_scheme, publisher, hmac_key, topic, batch, opt.payload_bytes, prev, seq, epoch);
                        } else {
                            ev = make_a6_evidence(sig_scheme, publisher, witness_keys, hmac_key, topic, batch, opt.payload_bytes, prev, seq, epoch);
                        }
                        prev = ev.checkpoint.end_anchor;
                        seq += static_cast<std::uint32_t>(batch);
                        ++epoch;
                        ComponentSizes s = component_sizes(ev);
                        total.checkpoint_metadata_bytes += s.checkpoint_metadata_bytes;
                        total.signature_bytes += s.signature_bytes;
                        total.public_key_bytes += s.public_key_bytes;
                        total.records_raw_bytes += s.records_raw_bytes;
                        total.merkle_proofs_raw_bytes += s.merkle_proofs_raw_bytes;
                        total.chain_seed_bytes += s.chain_seed_bytes;
                        total.chain_values_raw_bytes += s.chain_values_raw_bytes;
                        total.witness_receipts_raw_bytes += s.witness_receipts_raw_bytes;
                        total.full_evidence_raw_bytes += s.full_evidence_raw_bytes;
                    }
                }

                const std::size_t total_bytes = online_record_wire + total.full_evidence_raw_bytes;
                Row row;
                row["arm"] = arm;
                row["N"] = std::to_string(requested_n);
                row["effective_N"] = std::to_string(effective_n);
                row["witness_count"] = std::to_string(m);
                row["payload_bytes"] = std::to_string(opt.payload_bytes);
                row["n_msgs"] = std::to_string(n_msgs);
                row["online_record_wire_bytes"] = std::to_string(online_record_wire);
                row["evidence_package_bytes"] = std::to_string(total.full_evidence_raw_bytes);
                row["total_wire_bytes"] = std::to_string(total_bytes);
                row["evidence_bytes_per_msg"] = format_double(static_cast<double>(total.full_evidence_raw_bytes) / n_msgs, 2);
                row["amortized_bytes_per_msg"] = format_double(static_cast<double>(total_bytes) / n_msgs, 2);
                row["amortized_vs_payload_ratio"] = format_double(static_cast<double>(total_bytes) / n_msgs / opt.payload_bytes, 4);
                row["authenticated_wire_payload_bytes"] = std::to_string(wire_payload_bytes);
                row["measurement_scope"] = "authenticated_wire_envelope_v1_plus_raw_checkpoint_evidence_cpp";
                add_component_fields(row, total);
                rows.push_back(std::move(row));
            }
        }
    }
    return rows;
}

static std::size_t selected_merkle_proof_bytes(const Evidence &ev, std::size_t k) {
    std::size_t total = ev.signature.size();
    const std::size_t limit = std::min(k, ev.merkle_proofs.size());
    for (std::size_t i = 0; i < limit; ++i) {
        for (const ProofStep &step : ev.merkle_proofs[i]) {
            total += step.sibling.size() + 1;
        }
    }
    return total;
}

static std::vector<Row> run_e8_audit_cost_cpp(const Options &opt) {
    std::cout << "E8 C++ audit verification cost\n";
    std::vector<Row> rows;
    OqsSig sig_scheme(kSigMain);
    OqsSigKey publisher(sig_scheme, "publisher");
    const Bytes hmac_key = make_hmac_key_once();

    std::size_t a3_last_n = 0;  // A3 is full-chain; emit once per N, not per (N,k)
    for (std::size_t n : batch_sizes(opt)) {
        for (std::size_t k : k_values(opt)) {
            if (k > n) {
                continue;
            }
            const Bytes zero(kHashBytes, 0);
            if (n != a3_last_n) {
                a3_last_n = n;
                const std::string topic = topic_for("A3");
                const PublisherTrust trust = publisher_trust(publisher, topic);
                Evidence ev = make_a3_evidence(sig_scheme, publisher, hmac_key, topic, n, opt.payload_bytes, zero, 1, 0);
                Stats stats = time_op([&]() {
                    if (!verify_a3(ev, sig_scheme, true, trust)) {
                        throw std::runtime_error("A3 verify failed");
                    }
                }, opt.audit_runs, opt.warmup);
                ComponentSizes sizes = component_sizes(ev);
                Row row;
                row["arm"] = "A3";
                row["N"] = std::to_string(n);
                row["k_disclosed"] = std::to_string(n);
                row["proof_bytes"] = std::to_string(sizes.chain_seed_bytes + sizes.chain_values_raw_bytes + sizes.signature_bytes);
                row["full_evidence_bytes"] = std::to_string(sizes.full_evidence_raw_bytes);
                row["verify_scope"] = "full_chain_plus_checkpoint_signature";
                row["disclosure_model"] = "full_chain_requires_all_records";
                row["verify_signature_count"] = "1";
                row["chain_records_replayed"] = std::to_string(n);
                row["merkle_proofs_verified"] = "0";
                row["witness_quorum_verified"] = "0";
                put_stats(row, "verify", stats);
                row["n_repetitions"] = std::to_string(opt.audit_runs);
                rows.push_back(std::move(row));
            }
            {
                const std::string topic = topic_for("A4");
                const PublisherTrust trust = publisher_trust(publisher, topic);
                Evidence ev = make_a4_evidence(sig_scheme, publisher, hmac_key, topic, n, opt.payload_bytes, zero, 1, 0);
                Stats stats = time_op([&]() {
                    if (!verify_a4(ev, sig_scheme, k, true, trust)) {
                        throw std::runtime_error("A4 verify failed");
                    }
                }, opt.audit_runs, opt.warmup);
                ComponentSizes sizes = component_sizes(ev);
                Row row;
                row["arm"] = "A4";
                row["N"] = std::to_string(n);
                row["k_disclosed"] = std::to_string(k);
                row["proof_bytes"] = std::to_string(selected_merkle_proof_bytes(ev, k));
                row["full_evidence_bytes"] = std::to_string(sizes.full_evidence_raw_bytes);
                row["verify_scope"] = "selected_merkle_inclusions_plus_checkpoint_signature";
                row["disclosure_model"] = "selective_merkle_inclusion";
                row["verify_signature_count"] = "1";
                row["chain_records_replayed"] = "0";
                row["merkle_proofs_verified"] = std::to_string(k);
                row["witness_quorum_verified"] = "0";
                put_stats(row, "verify", stats);
                row["n_repetitions"] = std::to_string(opt.audit_runs);
                rows.push_back(std::move(row));
            }
            for (std::size_t m : witness_counts(opt)) {
                std::vector<OqsSigKey> witnesses;
                for (std::size_t i = 0; i < m; ++i) {
                    witnesses.emplace_back(sig_scheme, "witness-" + std::to_string(i + 1));
                }
                Evidence ev = make_a6_evidence(sig_scheme, publisher, witnesses, hmac_key, topic_for("A6"), n, opt.payload_bytes, zero, 1, 0);
                const PublisherTrust trust = publisher_trust(publisher, topic_for("A6"));
                const WitnessRegistry registry = witness_registry(witnesses);
                const std::size_t min_receipts = std::min<std::size_t>(m, (m / 2) + 1);
                WitnessPolicy policy;
                policy.min_receipts = min_receipts;
                Stats stats = time_op([&]() {
                    if (!verify_a6(ev, sig_scheme, k, policy, trust, registry)) {
                        throw std::runtime_error("A6 verify failed");
                    }
                }, opt.audit_runs, opt.warmup);
                ComponentSizes sizes = component_sizes(ev);
                Row row;
                row["arm"] = "A6";
                row["N"] = std::to_string(n);
                row["k_disclosed"] = std::to_string(k);
                row["witness_count"] = std::to_string(m);
                row["min_receipts"] = std::to_string(min_receipts);
                row["proof_bytes"] = std::to_string(selected_merkle_proof_bytes(ev, k) + sizes.witness_receipts_raw_bytes);
                row["full_evidence_bytes"] = std::to_string(sizes.full_evidence_raw_bytes);
                row["verify_scope"] = "selected_merkle_checkpoint_signature_and_witness_quorum";
                row["disclosure_model"] = "selective_merkle_with_witness_receipts";
                row["verify_signature_count"] = "1";
                row["chain_records_replayed"] = "0";
                row["merkle_proofs_verified"] = std::to_string(k);
                row["witness_quorum_verified"] = std::to_string(m);
                put_stats(row, "verify", stats);
                row["n_repetitions"] = std::to_string(opt.audit_runs);
                rows.push_back(std::move(row));
            }
        }
    }
    return rows;
}

static std::vector<Row> run_a6_witness_cost_cpp(const Options &opt) {
    std::cout << "A6 C++ witness cost decomposition\n";
    std::vector<Row> rows;
    OqsSig sig_scheme(kSigMain);
    OqsSigKey publisher(sig_scheme, "publisher");
    const Bytes hmac_key = make_hmac_key_once();
    const Bytes zero(kHashBytes, 0);
    const std::size_t n = opt.mode == "quick" ? 100 : 500;
    Evidence base = make_a4_evidence(sig_scheme, publisher, hmac_key, topic_for("A6"), n, opt.payload_bytes, zero, 1, 0);

    for (std::size_t m : witness_counts(opt)) {
        std::vector<OqsSigKey> witnesses;
        for (std::size_t i = 0; i < m; ++i) {
            witnesses.emplace_back(sig_scheme, "witness-" + std::to_string(i + 1));
        }
        std::vector<WitnessReceipt> receipts;
        receipts.reserve(m);
        for (const auto &w : witnesses) {
            receipts.push_back(make_witness_receipt(sig_scheme, w, base.checkpoint));
        }

        auto add_op = [&](const std::string &operation, const Stats &stats, std::size_t bytes, std::size_t min_receipts) {
            Row row;
            row["operation"] = operation;
            row["N"] = std::to_string(n);
            row["witness_count"] = std::to_string(m);
            row["min_receipts"] = std::to_string(min_receipts);
            row["bytes"] = std::to_string(bytes);
            put_stats(row, "cost", stats);
            row["n_repetitions"] = std::to_string(opt.audit_runs);
            rows.push_back(std::move(row));
        };

        Stats sign_one = time_op([&]() {
            WitnessReceipt r = make_witness_receipt(sig_scheme, witnesses.front(), base.checkpoint);
            if (r.signature.empty()) {
                throw std::runtime_error("empty witness signature");
            }
        }, opt.audit_runs, opt.warmup);
        add_op("one_witness_receipt_sign", sign_one, receipts.front().body().size() + receipts.front().signature.size() + receipts.front().public_key.size(), 1);

        Stats sign_all = time_op([&]() {
            std::vector<WitnessReceipt> tmp;
            for (const auto &w : witnesses) {
                tmp.push_back(make_witness_receipt(sig_scheme, w, base.checkpoint));
            }
            if (tmp.size() != witnesses.size()) {
                throw std::runtime_error("missing witness receipt");
            }
        }, opt.audit_runs, opt.warmup);
        std::size_t all_bytes = 0;
        for (const WitnessReceipt &r : receipts) {
            all_bytes += r.body().size() + r.signature.size() + r.public_key.size();
        }
        add_op("all_witness_receipts_sign", sign_all, all_bytes, m);

        Evidence ev = base;
        ev.arm = "A6";
        ev.witness_receipts = receipts;
        const WitnessRegistry registry = witness_registry(witnesses);
        const std::size_t threshold = std::min<std::size_t>(m, (m / 2) + 1);
        WitnessPolicy policy;
        policy.min_receipts = threshold;
        Stats verify_threshold = time_op([&]() {
            if (!verify_witness_receipts(ev, sig_scheme, policy, registry)) {
                throw std::runtime_error("witness threshold verify failed");
            }
        }, opt.audit_runs, opt.warmup);
        add_op("verify_witness_quorum", verify_threshold, all_bytes, threshold);
    }
    return rows;
}

struct StatefulWitness {
    OqsSigKey key;
    Bytes latest_anchor = Bytes(kHashBytes, 0);
    explicit StatefulWitness(OqsSig &scheme) : key(scheme, "stateful-witness") {}

    std::optional<WitnessReceipt> issue(OqsSig &scheme, const Checkpoint &ckpt) {
        if (ckpt.prev_anchor != latest_anchor) {
            return std::nullopt;
        }
        WitnessReceipt r = make_witness_receipt(scheme, key, ckpt);
        latest_anchor = ckpt.end_anchor;
        return r;
    }
};

static std::vector<Row> run_a6_failure_grid_cpp(const Options &opt) {
    std::cout << "A6 C++ failure grid\n";
    std::vector<Row> rows;
    OqsSig sig_scheme(kSigMain);
    OqsSigKey publisher(sig_scheme, "publisher");
    std::vector<OqsSigKey> witnesses;
    for (std::size_t i = 0; i < 3; ++i) {
        witnesses.emplace_back(sig_scheme, "witness-" + std::to_string(i + 1));
    }
    const Bytes hmac_key = make_hmac_key_once();
    const Bytes zero(kHashBytes, 0);
    const double now = now_unix_double();
    Evidence current = make_a6_evidence(sig_scheme, publisher, witnesses, hmac_key, topic_for("A6"), 100, opt.payload_bytes, zero, 1, 0, now);
    Evidence old = make_a6_evidence(sig_scheme, publisher, witnesses, hmac_key, topic_for("A6"), 100, opt.payload_bytes, zero, 1, 0, now - 3600.0);
    Evidence no_receipts = current;
    no_receipts.witness_receipts.clear();
    Evidence one_receipt = current;
    one_receipt.witness_receipts.resize(1);
    const PublisherTrust trust = publisher_trust(publisher, topic_for("A6"));
    const WitnessRegistry registry = witness_registry(witnesses);

    auto add_case = [&](const std::string &name, const Evidence &ev, WitnessPolicy policy, bool expected_accept, const std::string &detection_class) {
        const bool accepted = verify_a6(
            ev,
            sig_scheme,
            std::min<std::size_t>(1, ev.records.size()),
            policy,
            trust,
            registry);
        Row row;
        row["case"] = name;
        row["accepted"] = accepted ? "true" : "false";
        row["expected_accept"] = expected_accept ? "true" : "false";
        row["matches_expected"] = (accepted == expected_accept) ? "true" : "false";
        row["min_receipts"] = std::to_string(policy.min_receipts);
        row["freshness_window_s"] = policy.freshness_window_s.has_value() ? format_double(policy.freshness_window_s.value(), 1) : "";
        row["latest_anchor_required"] = policy.latest_anchor.has_value() ? "true" : "false";
        row["receipt_count"] = std::to_string(ev.witness_receipts.size());
        row["detection_class"] = detection_class;
        rows.push_back(std::move(row));
    };

    WitnessPolicy quorum2;
    quorum2.min_receipts = 2;
    quorum2.now = now;
    add_case("valid_current_quorum2", current, quorum2, true, "accept_valid");

    WitnessPolicy no_fresh = quorum2;
    add_case("rollback_old_valid_without_freshness", old, no_fresh, true, "limitation_self_contained_old_evidence_accepts");

    WitnessPolicy fresh = quorum2;
    fresh.freshness_window_s = 60.0;
    fresh.now = now;
    add_case("rollback_old_valid_with_freshness", old, fresh, false, "detectable_with_freshness");

    WitnessPolicy latest = quorum2;
    latest.latest_anchor = current.checkpoint.end_anchor;
    add_case("tail_truncation_old_checkpoint_with_latest_anchor", old, latest, false, "detectable_with_latest_witness_state");

    add_case("witness_unavailable", no_receipts, quorum2, false, "detectable_policy_failure");
    add_case("below_quorum", one_receipt, quorum2, false, "detectable_policy_failure");

    Evidence duplicate_receipt = current;
    duplicate_receipt.witness_receipts = {
        current.witness_receipts.front(),
        current.witness_receipts.front(),
    };
    add_case(
        "duplicate_witness_receipt_cannot_reach_quorum",
        duplicate_receipt,
        quorum2,
        false,
        "rejected_duplicate_trusted_identity");

    OqsSigKey untrusted_witness(sig_scheme, "untrusted-witness");
    Evidence untrusted_receipt = current;
    untrusted_receipt.witness_receipts = {
        make_witness_receipt(sig_scheme, untrusted_witness, current.checkpoint),
        current.witness_receipts.front(),
    };
    add_case(
        "untrusted_witness_cannot_reach_quorum",
        untrusted_receipt,
        quorum2,
        false,
        "rejected_unknown_witness_identity");

    OqsSigKey attacker_publisher(sig_scheme, "attacker-publisher");
    Evidence self_signed = make_a6_evidence(
        sig_scheme,
        attacker_publisher,
        witnesses,
        hmac_key,
        topic_for("A6"),
        100,
        opt.payload_bytes,
        zero,
        1,
        0,
        now);
    add_case(
        "self_signed_publisher_rejected",
        self_signed,
        quorum2,
        false,
        "rejected_publisher_registry_mismatch");

    Evidence future_receipts = current;
    future_receipts.witness_receipts.clear();
    for (const OqsSigKey &witness : witnesses) {
        future_receipts.witness_receipts.push_back(
            make_witness_receipt(sig_scheme, witness, current.checkpoint, now + 3600.0));
    }
    add_case(
        "future_witness_timestamp_rejected",
        future_receipts,
        quorum2,
        false,
        "rejected_future_timestamp");

    StatefulWitness sw(sig_scheme);
    Evidence fork1 = make_a4_evidence(sig_scheme, publisher, hmac_key, topic_for("A6"), 100, opt.payload_bytes, zero, 1, 0);
    Evidence fork2 = make_a4_evidence(sig_scheme, publisher, hmac_key, topic_for("A6"), 100, opt.payload_bytes, zero, 1, 0);
    auto r1 = sw.issue(sig_scheme, fork1.checkpoint);
    auto r2 = sw.issue(sig_scheme, fork2.checkpoint);
    Row split;
    split["case"] = "split_view_same_witness_extension_only";
    split["accepted"] = "false";
    split["expected_accept"] = "false";
    split["matches_expected"] = (!r2.has_value()) ? "true" : "false";
    split["first_receipt_issued"] = r1.has_value() ? "true" : "false";
    split["second_receipt_issued"] = r2.has_value() ? "true" : "false";
    split["detection_class"] = "blocked_by_extension_only_witness_state";
    rows.push_back(std::move(split));

    return rows;
}

static void run_primitive_outputs(const Options &opt, const Provenance &prov) {
    std::cout << "Primitive C++ benchmarks\n";
    std::vector<Row> bench = bench_kems(opt);
    std::vector<Row> sig_rows = bench_sigs(opt);
    std::vector<Row> classical = bench_classical(opt);
    bench.insert(bench.end(), sig_rows.begin(), sig_rows.end());
    bench.insert(bench.end(), classical.begin(), classical.end());
    std::vector<Row> sizes = object_sizes(opt);
    write_csv(prov.result_dir / "bench_crypto_cpp.csv", bench, prov);
    write_csv(prov.result_dir / "object_sizes_cpp.csv", sizes, prov);
    if (opt.legacy_names) {
        write_csv(prov.result_dir / "bench_crypto.csv", bench, prov);
        write_csv(prov.result_dir / "object_sizes.csv", sizes, prov);
    }
}

static void run_audit_outputs(const Options &opt, const Provenance &prov) {
    write_csv(prov.result_dir / "e4_amortized_overhead_cpp.csv", run_e4_amortized_cpp(opt), prov);
    write_csv(prov.result_dir / "e8_audit_cost_cpp.csv", run_e8_audit_cost_cpp(opt), prov);
    write_csv(prov.result_dir / "a6_witness_cost_cpp.csv", run_a6_witness_cost_cpp(opt), prov);
    write_csv(prov.result_dir / "a6_failure_grid_cpp.csv", run_a6_failure_grid_cpp(opt), prov);
}

static std::string to_hex(const Bytes &b) {
    static const char *hexdig = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (std::uint8_t byte : b) {
        out.push_back(hexdig[byte >> 4]);
        out.push_back(hexdig[byte & 0x0f]);
    }
    return out;
}

// Deterministic known-answer self-test. Emits a JSON object of hashes and object
// sizes over a fixed canonical input. Every field MUST match the Python
// implementation byte-for-byte; crosscheck/crosscheck.py consumes this to prove
// the two toolchains share identical record serialization, Merkle construction,
// hash-chain, checkpoint, and witness-body logic. No timing, no randomness.
static int run_selftest() {
    const std::string topic = "aapa/xcheck/telemetry";
    const std::string client_id = kClientId;
    const std::size_t payload_bytes = 64;
    const std::size_t n = 8;

    std::vector<Bytes> ser;
    ser.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        Record rec;
        rec.seq = static_cast<std::uint32_t>(i + 1);
        rec.ts = 1700000000.0 + static_cast<double>(i) * 0.5;
        rec.topic = topic;
        rec.payload = payload_pattern(payload_bytes, rec.seq);
        ser.push_back(rec.serialize());
    }

    const std::string record0 = to_hex(sha256(ser[0]));

    MerkleTree tree8;
    for (const Bytes &s : ser) {
        tree8.append(s);
    }
    const Bytes root8 = tree8.build();

    MerkleTree tree5;
    for (std::size_t i = 0; i < 5; ++i) {
        tree5.append(ser[i]);
    }
    const Bytes root5 = tree5.build();

    HashChain chain(Bytes(kHashBytes, 0x2a));
    for (const Bytes &s : ser) {
        chain.append(s);
    }
    const Bytes chain_head = chain.head();

    Checkpoint ckpt = make_checkpoint(topic, 7, 1, 8, Bytes(kHashBytes, 0), root8, 1700000042.5);
    const std::string ckpt_hash = to_hex(sha256(ckpt.serialize()));

    WitnessReceipt wr;
    wr.witness_id = "witness-1";
    wr.stream_id = canonical_stream_id(client_id, topic);
    wr.checkpoint_epoch = 7;
    wr.seq_start = 1;
    wr.seq_end = 8;
    wr.prev_witnessed_anchor = Bytes(kHashBytes, 0);
    wr.checkpoint_anchor = root8;
    wr.ts_witness = 1700000043.0;
    const std::string wr_hash = to_hex(sha256(wr.body()));

    const Proof proof3 = tree8.proof(3);
    const bool verify3 = MerkleTree::verify(ser[3], proof3, root8);

    // Actual object sizes (ML-KEM/ML-DSA are fixed length, so this matches Python).
    OqsSig sig_scheme(kSigMain);
    auto [sig_pk, sig_sk] = sig_scheme.keypair();
    const Bytes sig_bytes = sig_scheme.sign(str_bytes("size probe"), sig_sk);
    OqsKem kem_scheme(kKemMain);
    auto [kem_pk, kem_sk] = kem_scheme.keypair();
    auto [kem_ct, kem_ss] = kem_scheme.encaps(kem_pk);

    std::ostringstream js;
    js << "{"
       << "\"schema\":\"aapa-xcheck-v1\","
       << "\"impl\":\"cpp\","
       << "\"record0_ser_sha256\":\"" << record0 << "\","
       << "\"merkle_root_8\":\"" << to_hex(root8) << "\","
       << "\"merkle_root_5\":\"" << to_hex(root5) << "\","
       << "\"chain_head_8\":\"" << to_hex(chain_head) << "\","
       << "\"checkpoint_ser_sha256\":\"" << ckpt_hash << "\","
       << "\"witness_body_sha256\":\"" << wr_hash << "\","
       << "\"merkle_proof_leaf3_verify\":" << (verify3 ? "true" : "false") << ","
       << "\"merkle_proof_leaf3_steps\":" << proof3.size() << ","
       << "\"ml_dsa_65_sig_bytes\":" << sig_bytes.size() << ","
       << "\"ml_dsa_65_pk_bytes\":" << sig_pk.size() << ","
       << "\"ml_dsa_65_sk_bytes\":" << sig_sk.size() << ","
       << "\"ml_kem_768_pk_bytes\":" << kem_pk.size() << ","
       << "\"ml_kem_768_sk_bytes\":" << kem_sk.size() << ","
       << "\"ml_kem_768_ct_bytes\":" << kem_ct.size() << ","
       << "\"ml_kem_768_ss_bytes\":" << kem_ss.size()
       << "}";
    std::cout << js.str() << "\n";
    return 0;
}

static Options parse_args(int argc, char **argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need_value = [&](const std::string &name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for " + name);
            }
            return argv[++i];
        };
        if (arg == "--mode") {
            opt.mode = need_value(arg);
        } else if (arg == "--exp") {
            opt.exp = need_value(arg);
        } else if (arg == "--out-dir") {
            opt.out_dir = need_value(arg);
        } else if (arg == "--runs") {
            opt.runs = std::stoi(need_value(arg));
        } else if (arg == "--audit-runs") {
            opt.audit_runs = std::stoi(need_value(arg));
        } else if (arg == "--warmup") {
            opt.warmup = std::stoi(need_value(arg));
        } else if (arg == "--payload") {
            opt.payload_bytes = static_cast<std::size_t>(std::stoul(need_value(arg)));
        } else if (arg == "--legacy-names") {
            opt.legacy_names = true;
        } else if (arg == "--selftest") {
            opt.selftest = true;
        } else if (arg == "--quick") {
            opt.mode = "quick";
        } else if (arg == "--full") {
            opt.mode = "full";
        } else if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: aapa_crypto_bench [--mode quick|full] [--exp all|primitive|audit]\n"
                << "                         [--runs N] [--audit-runs N] [--out-dir DIR]\n"
                << "                         [--payload BYTES] [--legacy-names] [--selftest]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }
    if (opt.mode != "quick" && opt.mode != "full") {
        throw std::runtime_error("--mode must be quick or full");
    }
    if (opt.exp != "all" && opt.exp != "primitive" && opt.exp != "audit") {
        throw std::runtime_error("--exp must be all, primitive, or audit");
    }
    if (opt.runs <= 0 || opt.audit_runs <= 0 || opt.warmup < 0) {
        throw std::runtime_error("runs/audit-runs must be positive and warmup must be nonnegative");
    }
    return opt;
}

int main(int argc, char **argv) {
    try {
        Options opt = parse_args(argc, argv);
        if (opt.selftest) {
            OQS_init();
            const int rc = run_selftest();
            OQS_destroy();
            return rc;
        }
        if (opt.mode == "quick") {
            opt.runs = std::min(opt.runs, 50);
            opt.audit_runs = std::min(opt.audit_runs, 30);
        }
        OQS_init();
        const Provenance prov = make_provenance(opt);
        std::cout << "AAPA C++ crypto/audit runner\n";
        std::cout << "  mode: " << prov.mode << "\n";
        std::cout << "  liboqs: " << OQS_version() << "\n";
        std::cout << "  output: " << prov.result_dir << "\n";

        if (opt.exp == "all" || opt.exp == "primitive") {
            run_primitive_outputs(opt, prov);
        }
        if (opt.exp == "all" || opt.exp == "audit") {
            run_audit_outputs(opt, prov);
        }
        OQS_destroy();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        OQS_destroy();
        return 1;
    }
}
