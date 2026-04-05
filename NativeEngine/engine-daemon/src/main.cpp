#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "sentinel_engine.h"

namespace fs = std::filesystem;

namespace
{
    struct cli_options
    {
        bool health {false};
        bool scan {false};
        bool realtime {false};
        std::map<std::string, std::string> values;
    };

    std::string escape_json(const std::string& value)
    {
        std::ostringstream output;
        for (const auto character : value)
        {
            switch (character)
            {
                case '\\': output << "\\\\"; break;
                case '"': output << "\\\""; break;
                case '\n': output << "\\n"; break;
                case '\r': output << "\\r"; break;
                case '\t': output << "\\t"; break;
                default: output << character; break;
            }
        }

        return output.str();
    }

    cli_options parse_args(int argc, char** argv)
    {
        cli_options options {};
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument {argv[index]};
            if (argument == "--health")
            {
                options.health = true;
                continue;
            }

            if (argument == "--scan")
            {
                options.scan = true;
                continue;
            }

            if (argument == "--realtime")
            {
                options.realtime = true;
                continue;
            }

            if (argument.rfind("--", 0) == 0 && index + 1 < argc)
            {
                options.values[argument.substr(2)] = argv[++index];
            }
        }

        return options;
    }

    std::vector<sentinel::engine::compiled_rule> load_rules_from_pack(const std::string& path)
    {
        std::ifstream input {path};
        if (!input)
        {
            return {};
        }

        const std::string content {
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()
        };

        const std::regex rule_regex(
            R"(\{\s*"RuleId"\s*:\s*"([^"]+)"\s*,\s*"RuleName"\s*:\s*"([^"]+)"\s*,\s*"RuleKind"\s*:\s*"([^"]+)"\s*,\s*"Pattern"\s*:\s*"([^"]*)"\s*,\s*"Severity"\s*:\s*"([^"]+)")");

        std::vector<sentinel::engine::compiled_rule> rules;
        for (std::sregex_iterator iterator {content.begin(), content.end(), rule_regex}, end; iterator != end; ++iterator)
        {
            const auto& match = *iterator;
            rules.push_back(sentinel::engine::compiled_rule {
                match[1].str(),
                match[2].str(),
                match[3].str(),
                match[4].str(),
                match[5].str()
            });
        }

        return rules;
    }

    std::vector<fs::path> enumerate_targets(const std::string& target_value)
    {
        std::vector<fs::path> targets;
        const auto separator = fs::path::preferred_separator == '\\' ? ';' : ':';
        std::stringstream stream {target_value};
        std::string segment;
        while (std::getline(stream, segment, separator))
        {
            if (segment.empty())
            {
                continue;
            }

            const fs::path root {segment};
            std::error_code error_code;
            if (fs::is_regular_file(root, error_code))
            {
                targets.push_back(root);
                continue;
            }

            if (fs::is_directory(root, error_code))
            {
                for (fs::recursive_directory_iterator iterator {root, fs::directory_options::skip_permission_denied, error_code}, end;
                     iterator != end;
                     iterator.increment(error_code))
                {
                    if (error_code)
                    {
                        error_code.clear();
                        continue;
                    }

                    if (iterator->is_regular_file(error_code))
                    {
                        targets.push_back(iterator->path());
                    }
                }
            }
        }

        return targets;
    }

    std::string emit_health_payload(const cli_options& options)
    {
        std::ostringstream output;
        output << "{"
               << "\"engineOnline\":true,"
               << "\"engineVersion\":\"" << escape_json(options.values.contains("engine-version") ? options.values.at("engine-version") : "native-scaffold") << "\","
               << "\"signaturePackVersion\":\"" << escape_json(options.values.contains("pack-version") ? options.values.at("pack-version") : "unloaded") << "\","
               << "\"parserCompatibilityVersion\":\"" << escape_json(options.values.contains("parser-version") ? options.values.at("parser-version") : "parser-1.0.0") << "\","
               << "\"realtimeMonitoringEnabled\":true,"
               << "\"daemonTransport\":\"native-process\","
               << "\"capturedAt\":\"2026-04-05T00:00:00Z\""
               << "}";
        return output.str();
    }

    std::string emit_scan_payload(const cli_options& options)
    {
        const auto pack_path = options.values.contains("pack") ? options.values.at("pack") : std::string {};
        const auto target_value = options.values.contains("target") ? options.values.at("target") : std::string {};
        auto rules = load_rules_from_pack(pack_path);
        auto targets = enumerate_targets(target_value);

        sentinel::engine::engine_core engine {};
        engine.load_rules(std::move(rules));

        std::vector<sentinel::engine::detection_record> detections;
        std::vector<std::string> detection_paths;
        std::ostringstream progress;
        progress << "[";

        const auto total_files = targets.size();
        std::size_t files_scanned = 0;
        for (const auto& target : targets)
        {
            sentinel::engine::file_artifact artifact {
                target.string(),
                target.filename().string(),
                fs::is_regular_file(target) ? fs::file_size(target) : 0,
                ""
            };

            const auto result = engine.scan_file(artifact);
            for (const auto& detection : result.detections)
            {
                detections.push_back(detection);
                detection_paths.push_back(target.string());
            }

            if (files_scanned > 0)
            {
                progress << ",";
            }

            const auto percent = total_files == 0 ? 100 : static_cast<int>((static_cast<double>(files_scanned + 1) / static_cast<double>(total_files)) * 90.0) + 5;
            progress << "{"
                     << "\"stage\":\"StaticAnalysis\","
                     << "\"percentComplete\":" << percent << ","
                     << "\"currentPath\":\"" << escape_json(target.string()) << "\","
                     << "\"filesScanned\":" << (files_scanned + 1) << ","
                     << "\"totalFiles\":" << total_files << ","
                     << "\"findingsCount\":" << detections.size()
                     << "}";
            ++files_scanned;
        }

        if (total_files == 0)
        {
            progress << "{"
                     << "\"stage\":\"Completed\","
                     << "\"percentComplete\":100,"
                     << "\"currentPath\":\"\","
                     << "\"filesScanned\":0,"
                     << "\"totalFiles\":0,"
                     << "\"findingsCount\":0"
                     << "}";
        }

        progress << "]";

        std::ostringstream output;
        output << "{"
               << "\"status\":\"Completed\","
               << "\"stage\":\"Completed\","
               << "\"percentComplete\":100,"
               << "\"filesScanned\":" << files_scanned << ","
               << "\"totalFiles\":" << total_files << ","
               << "\"currentTarget\":\"" << escape_json(target_value) << "\","
               << "\"progressEvents\":" << progress.str() << ","
               << "\"detections\":[";

        for (std::size_t index = 0; index < detections.size(); ++index)
        {
            const auto& detection = detections[index];
            if (index > 0)
            {
                output << ",";
            }

            output << "{"
                   << "\"ruleId\":\"" << escape_json(detection.rule_id) << "\","
                   << "\"engineName\":\"" << escape_json(detection.engine_name) << "\","
                   << "\"source\":\"ProprietaryStatic\","
                   << "\"severity\":\"" << escape_json(detection.severity) << "\","
                   << "\"confidence\":" << detection.confidence << ","
                   << "\"summary\":\"" << escape_json(detection.summary) << "\","
                   << "\"artifactPath\":\"" << escape_json(detection_paths[index]) << "\""
                   << "}";
        }

        output << "]"
               << "}";

        return output.str();
    }
}

int main(int argc, char** argv)
{
    const auto options = parse_args(argc, argv);

    if (options.health)
    {
        std::cout << emit_health_payload(options) << std::endl;
        return 0;
    }

    if (options.scan || options.realtime)
    {
        std::cout << emit_scan_payload(options) << std::endl;
        return 0;
    }

    std::cout << "{\"status\":\"Idle\",\"message\":\"Sentinel native engine daemon scaffold\"}" << std::endl;
    return 0;
}
