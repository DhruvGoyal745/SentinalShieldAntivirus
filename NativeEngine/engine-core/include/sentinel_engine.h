#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sentinel::engine
{
    enum class verdict
    {
        clean,
        suspicious,
        malicious,
        error,
        skipped
    };

    struct compiled_rule
    {
        std::string rule_id;
        std::string rule_name;
        std::string rule_kind;
        std::string pattern;
        std::string severity;
    };

    struct file_artifact
    {
        std::string full_path;
        std::string file_name;
        std::uint64_t size_bytes {0};
        std::string hash_sha256;
    };

    struct detection_record
    {
        std::string rule_id;
        std::string engine_name;
        std::string severity;
        double confidence {0.0};
        std::string summary;
    };

    struct scan_result
    {
        verdict final_verdict {verdict::clean};
        std::vector<detection_record> detections;
    };

    class engine_core
    {
    public:
        void load_rules(std::vector<compiled_rule> rules);
        scan_result scan_file(const file_artifact& artifact) const;

    private:
        std::vector<compiled_rule> rules_;
    };
}
