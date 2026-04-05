#include "sentinel_engine.h"

namespace sentinel::engine
{
    void engine_core::load_rules(std::vector<compiled_rule> rules)
    {
        rules_ = std::move(rules);
    }

    scan_result engine_core::scan_file(const file_artifact& artifact) const
    {
        scan_result result {};

        for (const auto& rule : rules_)
        {
            const auto matches = [&]()
            {
                if (rule.pattern.empty())
                {
                    return false;
                }

                if (rule.rule_kind == "Hash")
                {
                    return artifact.hash_sha256 == rule.pattern;
                }

                if (rule.rule_kind == "PathFragment")
                {
                    return artifact.full_path.find(rule.pattern) != std::string::npos;
                }

                return artifact.file_name.find(rule.pattern) != std::string::npos
                    || artifact.full_path.find(rule.pattern) != std::string::npos;
            }();

            if (matches)
            {
                result.detections.push_back(detection_record {
                    rule.rule_id,
                    "Sentinel Native Static Engine",
                    rule.severity,
                    0.85,
                    "Native scaffold matched file-name rule."
                });
            }
        }

        if (!result.detections.empty())
        {
            result.final_verdict = verdict::suspicious;
        }

        return result;
    }
}
