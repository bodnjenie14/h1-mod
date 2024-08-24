#include <std_include.hpp>
#include "auth3_server.hpp"
#include "../keys.hpp"

#include <utils/cryptography.hpp>
#include <utils/string.hpp>
#include <fstream>  // Include for file operations

namespace demonware
{
//    namespace
//    {
//#pragma pack(push, 1)
//        struct auth_ticket
//        {
//            unsigned int m_magicNumber;
//            char m_type;
//            unsigned int m_titleID;
//            unsigned int m_timeIssued;
//            unsigned int m_timeExpires;
//            unsigned __int64 m_licenseID;
//            unsigned __int64 m_userID;
//            char m_username[64];
//            char m_sessionKey[24];
//            char m_usingHashMagicNumber[3];
//            char m_hash[4];
//        };
//#pragma pack(pop)
//    }
//
//    void auth3_server::send_reply(reply* data)
//    {
//        if (!data) return;
//        this->send(data->data());
//    }
//
//    void auth3_server::handle(const std::string& packet)
//    {
//        if (packet.starts_with("POST /auth/"))
//        {
//            printf("[DW]: [auth]: user requested authentication.\n");
//
//            return;
//        }
//
//        unsigned int title_id = 0;
//        unsigned int iv_seed = 0;
//        std::string identity{};
//        std::string token{};
//        std::string token_b64{};
//
//        rapidjson::Document j;
//        j.Parse(packet.data(), packet.size());
//
//        if (j.HasMember("title_id") && j["title_id"].IsString())
//        {
//            title_id = std::stoul(j["title_id"].GetString());
//        }
//
//        if (j.HasMember("iv_seed") && j["iv_seed"].IsString())
//        {
//            iv_seed = std::stoul(j["iv_seed"].GetString());
//        }
//
//        if (j.HasMember("identity") && j["identity"].IsString())
//        {
//            identity = j["identity"].GetString();
//        }
//
//        if (j.HasMember("extra_data") && j["extra_data"].IsString())
//        {
//            rapidjson::Document extra_data;
//            auto& ed = j["extra_data"];
//            extra_data.Parse(ed.GetString(), ed.GetStringLength());
//
//            if (extra_data.HasMember("token") && extra_data["token"].IsString())
//            {
//                auto& token_field = extra_data["token"];
//                token_b64 = std::string(token_field.GetString(), token_field.GetStringLength());
//                token = utils::cryptography::base64::decode(token_b64);
//            }
//        }
//
//        // Log the encoded and decoded tokens to a file
//        std::ofstream log_file("token_log.txt", std::ios::app);
//        if (log_file.is_open())
//        {
//            log_file << "Encoded token: " << token_b64 << "\n";
//            log_file << "Decoded token (raw): " << token << "\n";
//            log_file << "Decoded token (hex): " << utils::string::dump_hex(token) << "\n";
//
//            // Parse the decoded token
//            if (token.size() >= 128) // Ensure the token has enough data
//            {
//                // Extract parts of the token
//                auto magic_number = *reinterpret_cast<const unsigned int*>(token.data());
//                auto protocol = static_cast<unsigned char>(token[4]);
//                auto user_id = *reinterpret_cast<const unsigned long long*>(token.data() + 56);
//                auto username = std::string(token.data() + 64, 64);
//                auto session_key = std::string(token.data() + 32, 24);
//
//                // Trim null characters from username
//                username.erase(std::find(username.begin(), username.end(), '\0'), username.end());
//
//                log_file << "Magic Number: " << std::hex << magic_number << "\n";
//                log_file << "Protocol: " << static_cast<int>(protocol) << "\n";
//                log_file << "User ID: " << std::hex << user_id << "\n";
//                log_file << "Username: " << username << "\n";
//                log_file << "Session Key (hex): " << utils::string::dump_hex(session_key) << "\n";
//            }
//            else
//            {
//                log_file << "Token does not contain expected data.\n";
//            }
//
//            log_file.close();
//        }
//
//#ifdef DW_DEBUG
//        printf("[DW]: [auth]: authenticating user %s\n", token.data() + 64);
//#endif
//
//        // Extract authentication key from token
//        std::string auth_key(token.data() + 32, 24);
//        std::string session_key(
//            "\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37\x13\x37", 24);
//
//        // Create and initialize the client ticket
//        auth_ticket ticket{};
//        std::memset(&ticket, 0x0, sizeof ticket);
//        ticket.m_magicNumber = 0x0EFBDADDE;
//        ticket.m_type = 0;
//        ticket.m_titleID = title_id;
//        ticket.m_timeIssued = static_cast<uint32_t>(time(nullptr));
//        ticket.m_timeExpires = ticket.m_timeIssued + 30000;
//        ticket.m_licenseID = 0;
//        ticket.m_userID = *reinterpret_cast<const uint64_t*>(token.data() + 56);
//        strncpy_s(ticket.m_username, sizeof(ticket.m_username), token.data() + 64, 64);
//        std::memcpy(ticket.m_sessionKey, session_key.data(), 24);
//
//        // Generate IV and encrypt the ticket
//        const auto iv = utils::cryptography::tiger::compute(std::string(reinterpret_cast<char*>(&iv_seed), 4));
//        const auto ticket_enc = utils::cryptography::des3::encrypt(
//            std::string(reinterpret_cast<char*>(&ticket), sizeof(ticket)), iv, auth_key);
//        const auto ticket_b64 = utils::cryptography::base64::encode(
//            reinterpret_cast<const unsigned char*>(ticket_enc.data()), static_cast<unsigned int>(ticket_enc.size()));
//
//        // Create server ticket data
//        uint8_t auth_data[128];
//        std::memset(&auth_data, 0, sizeof auth_data);
//        std::memcpy(auth_data, session_key.data(), 24);
//        const auto auth_data_b64 = utils::cryptography::base64::encode(auth_data, 128);
//
//        // Set session key for future use
//        demonware::set_session_key(session_key);
//
//        // Generate HTTP date header
//        char date[64];
//        const auto now = time(nullptr);
//        tm gmtm{};
//        gmtime_s(&gmtm, &now);
//        strftime(date, 64, "%a, %d %b %G %T", &gmtm);
//
//        // Create JSON response content
//        rapidjson::Document doc;
//        doc.SetObject();
//
//        doc.AddMember("auth_task", "29", doc.GetAllocator());
//        doc.AddMember("code", "700", doc.GetAllocator());
//
//        auto seed = std::to_string(iv_seed);
//        doc.AddMember("iv_seed", rapidjson::StringRef(seed.data(), seed.size()), doc.GetAllocator());
//        doc.AddMember("client_ticket", rapidjson::StringRef(ticket_b64.data(), ticket_b64.size()), doc.GetAllocator());
//        //doc.AddMember("server_ticket", rapidjson::StringRef(auth_data_b64.data(), auth_data_b64.size()), doc.GetAllocator());
//        doc.AddMember("client_id", "", doc.GetAllocator());
//        doc.AddMember("account_type", "steam", doc.GetAllocator());
//        doc.AddMember("crossplay_enabled", false, doc.GetAllocator());
//        doc.AddMember("loginqueue_enabled", false, doc.GetAllocator());
//
//        rapidjson::Value value{};
//        doc.AddMember("lsg_endpoint", value, doc.GetAllocator());
//
//        rapidjson::StringBuffer buffer{};
//        rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>>
//            writer(buffer);
//        doc.Accept(writer);
//
//        // Create the HTTP response
//        std::string result;
//        result.append("HTTP/1.1 200 OK\r\n");
//        result.append("Server: TornadoServer/4.5.3\r\n");
//        result.append("Content-Type: application/json\r\n");
//        result.append(utils::string::va("Date: %s GMT\r\n", date));
//        result.append(utils::string::va("Content-Length: %d\r\n\r\n", buffer.GetLength()));
//        result.append(buffer.GetString(), buffer.GetLength());
//
//        // Log the response in a separate file
//        std::ofstream response_log_file("response_log.txt", std::ios::app);
//        if (response_log_file.is_open())
//        {
//            response_log_file << "Response:\n";
//            response_log_file << result << "\n";
//            response_log_file.close();
//        }
//
//        raw_reply reply(result);
//        this->send_reply(&reply);
//
//        printf("[DW]: [auth]: user successfully authenticated.\n");
//
//    }
}
