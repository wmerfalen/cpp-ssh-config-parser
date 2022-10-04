#ifndef __SSHCONFIGPARSER_LIB_PARSER_HEADER__
#define __SSHCONFIGPARSER_LIB_PARSER_HEADER__
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <map>

#include <linux/limits.h> /** For PATH_MAX */

//  TODO: Arguments may optionally be enclosed in double quotes (") in order
//       to represent arguments containing spaces
//  TODO: Configuration options may be separated by whitespace or
//      optional whitespace and exactly one ‘=’; the latter format is useful to avoid the need to quote
//	    whitespace when specifying configuration options using the ssh, scp, and sftp -o option.
//
//	TODO: Debian's openssh-client package sets several options as standard in
//			 /etc/ssh/ssh_config which are not the default in ssh(1):
//			 Include /etc/ssh/ssh_config.d/*.conf
//			 SendEnv LANG LC_*
//			 HashKnownHosts yes
//			 GSSAPIAuthentication yes


#define __SSHCONFIGPARSER_LIB_PARSER_DEBUG__

#if defined(__SSHCONFIGPARSER_LIB_PARSER_DEBUG__) || defined(__SSHCONFIGPARSER_ALL_DEBUG__)
	#define m_debug(A) std::cerr << "[debug]{" << __FILE__ << ":" << __LINE__ << "}->" << A << "\n";
#else
	#define m_debug(A)
#endif

#if defined(__SSHCONFIGPARSER_LIB_PARSER_MORE_DEBUG__) || defined(__SSHCONFIGPARSER_ALL_DEBUG__)
	#define m_more_debug(A) std::cerr << "[more-debug]{" << __FILE__ << ":" << __LINE__ << "}->" << A << "\n";
#else
	#define m_more_debug(A)
#endif

#if defined(__SSHCONFIGPARSER_LIB_PARSER_EXTRA_DEBUG__) || defined(__SSHCONFIGPARSER_ALL_DEBUG__)
	#define m_extra_debug(A) std::cerr << "[extra-debug]{" << __FILE__ << ":" << __LINE__ << "}->" << A << "\n";
#else
	#define m_extra_debug(A)
#endif

namespace ssh {
	namespace config {
		/** MAX_FILE_SIZE is 50 mib: 1024 * 1024 * 50 */
		static constexpr std::size_t MAX_FILE_SIZE = 1024 * 1024 * 50;
		// HOST_NAME_MAX is defined as 255 bytes
		// see man 2 gethostname
		static constexpr std::size_t MAX_HOSTNAME_LENGTH = 255;
		static constexpr std::size_t MAX_INCLUDE_LENGTH = PATH_MAX;

		static bool FILE_SIZE_TOO_BIG(const std::size_t& size) {
			return size > MAX_FILE_SIZE;
		}

		namespace util {
			static bool lower_case_compare(std::string_view a, std::string_view b) {
				for(unsigned i=0; i < a.length() && i < a.length() && i < b.length(); i++) {
					if(tolower(a[i]) != tolower(b[i])) {
						return false;
					}
				}
				return true;
			}
		};// end namespace util

		enum keys : uint16_t {
			AddressFamily,
			BatchMode,
			BindAddress,
			ChallengeResponseAuthentication,
			CheckHostIP,
			Cipher,
			Ciphers,
			Compression,
			CompressionLevel,
			ConnectionAttempts,
			ConnectTimeout,
			ControlMaster,
			ControlPath,
			DynamicForward,
			EnableSSHKeysign,
			EscapeChar,
			ExitOnForwardFailure,
			ForwardAgent,
			ForwardX11,
			ForwardX11Trusted,
			GatewayPorts,
			GlobalKnownHostsFile,
			GSSAPIAuthentication,
			GSSAPIClientIdentity,
			GSSAPIDelegateCredentials,
			GSSAPIKeyExchange,
			GSSAPIRenewalForcesRekey,
			GSSAPITrustDns,
			HashKnownHosts,
			Host,
			HostbasedAuthentication,
			HostKeyAlgorithms,
			HostKeyAlias,
			HostName,
			IdentitiesOnly,
			IdentityFile,
			KbdInteractiveAuthentication,
			KbdInteractiveDevices,
			LocalCommand,
			LocalForward,
			LogLevel,
			MACs,
			NumberOfPasswordPrompts,
			PasswordAuthentication,
			PermitLocalCommand,
			Port,
			PreferredAuthentications,
			Protocol,
			ProxyCommand,
			ProxyJump,
			PubkeyAuthentication,
			RekeyLimit,
			RemoteForward,
			RhostsRSAAuthentication,
			RSAAuthentication,
			SendEnv,
			ServerAliveCountMax,
			ServerAliveInterval,
			SmartcardDevice,
			StrictHostKeyChecking,
			TCPKeepAlive,
			Tunnel,
			TunnelDevice,
			UsePrivilegedPort,
			User,
			UserKnownHostsFile,
			VerifyHostKeyDNS,
			VisualHostKey,
			XAuthLocation,
			//
			//	Debian's openssh-client package sets several options as standard in
			//	 /etc/ssh/ssh_config which are not the default in ssh(1):
			//	 Include /etc/ssh/ssh_config.d/*.conf
			//	 SendEnv LANG LC_*
			//	 HashKnownHosts yes
			//	 GSSAPIAuthentication yes
			Include,
		};
		static std::optional<keys> from_string(std::string_view k) {
#define STR_TO_ENUM(A) if(util::lower_case_compare(k,#A)){ return keys::A; }
			STR_TO_ENUM(AddressFamily);
			STR_TO_ENUM(BatchMode);
			STR_TO_ENUM(BindAddress);
			STR_TO_ENUM(ChallengeResponseAuthentication);
			STR_TO_ENUM(CheckHostIP);
			STR_TO_ENUM(Cipher);
			STR_TO_ENUM(Ciphers);
			STR_TO_ENUM(Compression);
			STR_TO_ENUM(CompressionLevel);
			STR_TO_ENUM(ConnectionAttempts);
			STR_TO_ENUM(ConnectTimeout);
			STR_TO_ENUM(ControlMaster);
			STR_TO_ENUM(ControlPath);
			STR_TO_ENUM(DynamicForward);
			STR_TO_ENUM(EnableSSHKeysign);
			STR_TO_ENUM(EscapeChar);
			STR_TO_ENUM(ExitOnForwardFailure);
			STR_TO_ENUM(ForwardAgent);
			STR_TO_ENUM(ForwardX11);
			STR_TO_ENUM(ForwardX11Trusted);
			STR_TO_ENUM(GatewayPorts);
			STR_TO_ENUM(GlobalKnownHostsFile);
			STR_TO_ENUM(GSSAPIAuthentication);
			STR_TO_ENUM(GSSAPIClientIdentity);
			STR_TO_ENUM(GSSAPIDelegateCredentials);
			STR_TO_ENUM(GSSAPIKeyExchange);
			STR_TO_ENUM(GSSAPIRenewalForcesRekey);
			STR_TO_ENUM(GSSAPITrustDns);
			STR_TO_ENUM(HashKnownHosts);
			STR_TO_ENUM(Host);
			STR_TO_ENUM(HostbasedAuthentication);
			STR_TO_ENUM(HostKeyAlgorithms);
			STR_TO_ENUM(HostKeyAlias);
			STR_TO_ENUM(HostName);
			STR_TO_ENUM(IdentitiesOnly);
			STR_TO_ENUM(IdentityFile);
			STR_TO_ENUM(KbdInteractiveAuthentication);
			STR_TO_ENUM(KbdInteractiveDevices);
			STR_TO_ENUM(LocalCommand);
			STR_TO_ENUM(LocalForward);
			STR_TO_ENUM(LogLevel);
			STR_TO_ENUM(MACs);
			STR_TO_ENUM(NumberOfPasswordPrompts);
			STR_TO_ENUM(PasswordAuthentication);
			STR_TO_ENUM(PermitLocalCommand);
			STR_TO_ENUM(Port);
			STR_TO_ENUM(PreferredAuthentications);
			STR_TO_ENUM(Protocol);
			STR_TO_ENUM(ProxyCommand);
			STR_TO_ENUM(ProxyJump);
			STR_TO_ENUM(PubkeyAuthentication);
			STR_TO_ENUM(RekeyLimit);
			STR_TO_ENUM(RemoteForward);
			STR_TO_ENUM(RhostsRSAAuthentication);
			STR_TO_ENUM(RSAAuthentication);
			STR_TO_ENUM(SendEnv);
			STR_TO_ENUM(ServerAliveCountMax);
			STR_TO_ENUM(ServerAliveInterval);
			STR_TO_ENUM(SmartcardDevice);
			STR_TO_ENUM(StrictHostKeyChecking);
			STR_TO_ENUM(TCPKeepAlive);
			STR_TO_ENUM(Tunnel);
			STR_TO_ENUM(TunnelDevice);
			STR_TO_ENUM(UsePrivilegedPort);
			STR_TO_ENUM(User);
			STR_TO_ENUM(UserKnownHostsFile);
			STR_TO_ENUM(VerifyHostKeyDNS);
			STR_TO_ENUM(VisualHostKey);
			STR_TO_ENUM(XAuthLocation);
			/** Debian openssh-client constants */
			STR_TO_ENUM(Include);
			return std::nullopt;
#undef STR_TO_ENUM
		}
		static std::optional<std::string> to_string(keys k) {
#define KEY_ENUM_TO_STR(A) case keys::A: return #A;
			switch(k) {
					KEY_ENUM_TO_STR(AddressFamily);
					KEY_ENUM_TO_STR(BatchMode);
					KEY_ENUM_TO_STR(BindAddress);
					KEY_ENUM_TO_STR(ChallengeResponseAuthentication);
					KEY_ENUM_TO_STR(CheckHostIP);
					KEY_ENUM_TO_STR(Cipher);
					KEY_ENUM_TO_STR(Ciphers);
					KEY_ENUM_TO_STR(Compression);
					KEY_ENUM_TO_STR(CompressionLevel);
					KEY_ENUM_TO_STR(ConnectionAttempts);
					KEY_ENUM_TO_STR(ConnectTimeout);
					KEY_ENUM_TO_STR(ControlMaster);
					KEY_ENUM_TO_STR(ControlPath);
					KEY_ENUM_TO_STR(DynamicForward);
					KEY_ENUM_TO_STR(EnableSSHKeysign);
					KEY_ENUM_TO_STR(EscapeChar);
					KEY_ENUM_TO_STR(ExitOnForwardFailure);
					KEY_ENUM_TO_STR(ForwardAgent);
					KEY_ENUM_TO_STR(ForwardX11);
					KEY_ENUM_TO_STR(ForwardX11Trusted);
					KEY_ENUM_TO_STR(GatewayPorts);
					KEY_ENUM_TO_STR(GlobalKnownHostsFile);
					KEY_ENUM_TO_STR(GSSAPIAuthentication);
					KEY_ENUM_TO_STR(GSSAPIClientIdentity);
					KEY_ENUM_TO_STR(GSSAPIDelegateCredentials);
					KEY_ENUM_TO_STR(GSSAPIKeyExchange);
					KEY_ENUM_TO_STR(GSSAPIRenewalForcesRekey);
					KEY_ENUM_TO_STR(GSSAPITrustDns);
					KEY_ENUM_TO_STR(HashKnownHosts);
					KEY_ENUM_TO_STR(Host);
					KEY_ENUM_TO_STR(HostbasedAuthentication);
					KEY_ENUM_TO_STR(HostKeyAlgorithms);
					KEY_ENUM_TO_STR(HostKeyAlias);
					KEY_ENUM_TO_STR(HostName);
					KEY_ENUM_TO_STR(IdentitiesOnly);
					KEY_ENUM_TO_STR(IdentityFile);
					KEY_ENUM_TO_STR(KbdInteractiveAuthentication);
					KEY_ENUM_TO_STR(KbdInteractiveDevices);
					KEY_ENUM_TO_STR(LocalCommand);
					KEY_ENUM_TO_STR(LocalForward);
					KEY_ENUM_TO_STR(LogLevel);
					KEY_ENUM_TO_STR(MACs);
					KEY_ENUM_TO_STR(NumberOfPasswordPrompts);
					KEY_ENUM_TO_STR(PasswordAuthentication);
					KEY_ENUM_TO_STR(PermitLocalCommand);
					KEY_ENUM_TO_STR(Port);
					KEY_ENUM_TO_STR(PreferredAuthentications);
					KEY_ENUM_TO_STR(Protocol);
					KEY_ENUM_TO_STR(ProxyCommand);
					KEY_ENUM_TO_STR(ProxyJump);
					KEY_ENUM_TO_STR(PubkeyAuthentication);
					KEY_ENUM_TO_STR(RekeyLimit);
					KEY_ENUM_TO_STR(RemoteForward);
					KEY_ENUM_TO_STR(RhostsRSAAuthentication);
					KEY_ENUM_TO_STR(RSAAuthentication);
					KEY_ENUM_TO_STR(SendEnv);
					KEY_ENUM_TO_STR(ServerAliveCountMax);
					KEY_ENUM_TO_STR(ServerAliveInterval);
					KEY_ENUM_TO_STR(SmartcardDevice);
					KEY_ENUM_TO_STR(StrictHostKeyChecking);
					KEY_ENUM_TO_STR(TCPKeepAlive);
					KEY_ENUM_TO_STR(Tunnel);
					KEY_ENUM_TO_STR(TunnelDevice);
					KEY_ENUM_TO_STR(UsePrivilegedPort);
					KEY_ENUM_TO_STR(User);
					KEY_ENUM_TO_STR(UserKnownHostsFile);
					KEY_ENUM_TO_STR(VerifyHostKeyDNS);
					KEY_ENUM_TO_STR(VisualHostKey);
					KEY_ENUM_TO_STR(XAuthLocation);
					/** Debian openssh-client constants */
					KEY_ENUM_TO_STR(Include);
				default:
					m_debug("Unknown keyword found");
					return std::nullopt;
			}
#undef KEY_ENUM_TO_STR
		};
		struct host {
				void report() const {
					if(!parse_okay) {
						std::cout << "failed to parse host due to error: '" << parser_error << "'\n";
						return;
					}
					std::cout << "name: ";
					if(negated) {
						std::cout << "!";
					}
					std::cout << name << "\n";
				}

				host() = delete;
				host(std::string_view n) {
					parse_okay = parse(n);
				}
				bool parse(std::string_view input) {
					parser_error.clear();
					name.clear();
					parse_okay = negated = wildcard = false;
					std::string n;
					for(const auto& ch : input) {
						if(isspace(ch)) {
							continue;
						}
						if(ch == '!') {
							if(n.length() == 0) {
								negated = true;
								continue;
							}
							parse_okay = false;
							parser_error = "Error: found '!' in the wrong place";
							return false;
						}
						if(ch == '*') {
							wildcard = true;
						}
						name += ch;
						if(name.length() >= MAX_HOSTNAME_LENGTH) {
							break;
						}
					}
					return name.length() > 0;
				}
				std::string_view get_name() const {
					return name;
				}
				bool is_wildcard() const {
					return wildcard;
				}
				bool is_negated() const {
					return negated;
				}
				bool is_parsed_okay() const {
					return parse_okay;
				}
				std::string_view get_parser_error() const {
					return parser_error;
				}
			private:
				std::string name;
				bool wildcard;
				bool negated;
				bool parse_okay;
				std::string parser_error;
		};
		struct entry {
			enum type_t : uint8_t {
				HOST = 0,
				MATCH,
				INCLUDE,
			};
			entry() = delete;
			entry(type_t type,std::string_view line) {
				switch(type) {
					case type_t::HOST:
					case type_t::MATCH:
					default:
						parse_host(line);
						break;
					case type_t::INCLUDE:
						parse_includes(line);
						break;
				}
			}
			/**
			 * TODO: lock this behind getters/setters
			 */
			type_t type;
			std::vector<host> hosts;
			std::map<keys,std::string> data;
			std::vector<std::string> include_files;
			void report() const {
				for(const auto& host : hosts) {
					host.report();
				}
				for(const auto& pair : data) {
					std::cout << to_string(pair.first).value_or("invalid-key") << ": " << pair.second << "\n";
				}
			}
			void parse_host(std::string_view line) {
				std::string current;
				for(const auto& ch : line) {
					if(isspace(ch) && current.length()) {
						if(current.length() > MAX_HOSTNAME_LENGTH) {
							hosts.emplace_back(current.substr(0,MAX_HOSTNAME_LENGTH - 1));
						} else {
							hosts.emplace_back(current);
						}
						current.clear();
						continue;
					}
					current += ch;
				}
				if(current.length()) {
					hosts.emplace_back(current);
					m_debug("Host: '" << current << "'");
				}
			}
			void parse_includes(std::string_view line) {
				std::string current;
				for(const auto& ch : line) {
					if(isspace(ch) && current.length()) {
						if(current.length() > MAX_INCLUDE_LENGTH - 1) {
							include_files.emplace_back(current.substr(0,MAX_INCLUDE_LENGTH - 1));
						} else {
							include_files.emplace_back(current);
						}
						current.clear();
						continue;
					}
					current += ch;
				}
				if(current.length()) {
					include_files.emplace_back(current);
				}
			}
		};
		struct parser {
				parser(std::string_view config_file,const std::size_t& max_file_size) : parser() {
					m_max_file_size = max_file_size;
					good = false;
					open(config_file);
					close();
				}
				parser(std::string_view config_file) : parser() {
					m_max_file_size = MAX_FILE_SIZE;
					good = false;
					open(config_file);
					close();
				}
				parser() : m_max_file_size(MAX_FILE_SIZE),
					issue("none"), issue_line(0), line_number(0), m_file_size(0),
					m_fstream(nullptr), m_offset(0),m_stop_parse(false),m_entries(), good(false)
				{}
				~parser() {
					close();
				}
				const std::vector<entry>& get_entries() const {
					return m_entries;
				}
				void report() const {
					std::cout << "---------------------------------------------------\n";
					for(const auto& entry : m_entries) {
						entry.report();
						std::cout << "---------------------------------------------------\n";
					}
				}
				enum Symbol : uint16_t {
					letter,
					numeric,
					alnum,
					period,
					indent,
					whitespace,
					hash,
					colon,
					comment,
				};
				static constexpr std::string_view INCLUDE_STRING = "Include";
				static constexpr std::size_t INCLUDE_STRING_LENGTH = INCLUDE_STRING.length();
				static constexpr std::string_view HOST_STRING = "Host";
				static constexpr std::size_t HOST_STRING_LENGTH = HOST_STRING.length();
				static constexpr std::string_view MATCH_STRING = "Match";
				static constexpr std::size_t MATCH_STRING_LENGTH = MATCH_STRING.length();
				std::tuple<bool,std::size_t,std::string> start_parse() {
					line_number = 0;
					issue.clear();
					issue_line = 0;
					if(!good) {
						return {false,0,"not parsing. wasn't able to open file successfully"};
					}
					m_offset = 0;
					m_stop_parse = false;
					uint8_t add = 0;
					bool is_host = 0, is_match = 0;
					while(!eof()) {
						while(accept(whitespace)) {
							nextsym();
						}
						while(accept(comment)) {
							consume_line();
						}
						if(is_include_config()) {
							advance(INCLUDE_STRING_LENGTH);
							new_include_entry(capture_until_eol(MAX_INCLUDE_LENGTH));
							continue;
						}
						is_host = is_match = 0;
						add = 0;
						if(host()) {
							add = 4;
							is_host = true;
						}
						if(match()) {
							add = 5;
							is_match = true;
						}
						if(add) {
							advance(add);
							/** We found a Host/Match entry. capture the hosts */
							if(is_host) {
								new_host_entry(capture_until_eol(1024));
							}
							if(is_match) {
								new_match_entry(capture_until_eol(1024));
							}
							capture_indented_lines();
						}
					}
					if(issue_line) {
						return {false,issue_line,issue};
					}
					return {true,0,"parsed"};
				}
				void close() {
					if(m_fstream) {
						m_fstream->close();
						m_fstream = nullptr;
					}
				}
			private:
				std::size_t m_max_file_size;
				std::string issue;
				std::size_t issue_line;
				std::size_t line_number;
				std::size_t m_file_size;
				std::vector<char> buf;
				std::unique_ptr<std::fstream> m_fstream;
				std::size_t m_offset;
				bool m_stop_parse;
				std::vector<entry> m_entries;
				bool good;

				/**
				 * Returns a tuple of int32_t,std::size_t,std::string
				 * - int32_t -> status. zero means successfully opened file. negative means error
				 * - std::size_t -> number of bytes read from the file
				 * - std::string -> if error, will have a message about what happened. if success, should contain "opened file successfully"
				 */
				std::tuple<int32_t,std::size_t,std::string> open(std::string_view config_file) {
					m_fstream = std::make_unique<std::fstream>(config_file.data(),std::ifstream::in | std::ifstream::ate);
					if(!m_fstream->good()) {
						good = false;
						return {-1,0,"Couldn't open file"};
					}
					m_file_size = m_fstream->tellg();
					if(m_file_size > m_max_file_size) {
						m_fstream->close();
						good = false;
						return {-2,m_file_size,"File exceeds max file size"};
					}
					m_fstream->seekg(0);
					buf.resize(m_file_size+1);
					buf[m_file_size] = '\0';
					m_fstream->read(&buf[0],m_file_size);
					good = true;
					return {0,buf.size(),"opened file successfully"};
				}
				void new_host_entry(std::string&& line) {
					m_entries.emplace_back(entry::type_t::HOST,line);
				}
				void new_match_entry(std::string&& line) {
					m_entries.emplace_back(entry::type_t::MATCH,line);
				}
				void new_include_entry(std::string&& line) {
					m_debug("new_include_entry: '" << line << "'");
					m_entries.emplace_back(entry::type_t::INCLUDE,line);
				}
				const char& current_char() const {
					static const char EOF_BYTE = '\0';
					if(m_offset < buf.size()) {
						return buf[m_offset];
					}
					return EOF_BYTE;
				}
				std::string capture_until_whitespace(std::size_t max) {
					std::string current;
					auto it = buf.cbegin() + m_offset;
					while(!eof()) {
						nextsym();
						if(isspace(current_char())) {
							break;
						}
						current += current_char();
						if(current.length() >= max) {
							return current;
						}
					}
					return current;
				}
				void capture_indented_lines() {
					while(!eof()) {
						if(!expect(indent)) {
							if(accept(comment)) {
								consume_line();
								nextsym();
								continue;
							}
							rewind(1);
							issue_line = line_number;
							issue = "no indent. returning..\n";
							m_debug("capture_indented_lines error: '" << issue << "' on line_number: '" << issue_line << "'");
							return;
						}
						while(expect(indent)) {
							nextsym();
						}
						if(accept(comment)) {
							m_debug("comment accepted in indented line");
							consume_line();
							nextsym();
							continue;
						}
						if(!expect(alnum)) {
							issue_line = line_number;
							issue = std::string("expected alpha numeric, but got: '") + substr(10) + "'";
							m_debug("capture_indented_lines error: '" << issue << "' on line_number: '" << issue_line << "'");
							return;
						}
						rewind(1);
						auto key = capture_until_whitespace(256);
						auto opt_key = from_string(key);
						if(!opt_key.has_value()) {
							issue_line = line_number;
							issue = std::string("expected a valid key, instead got: '") + key + std::string("'");
							m_debug("capture_indented_lines error: '" << issue << "' on line_number: '" << issue_line << "'");
							eof_reached();
							return;
						}
						while(expect(whitespace)) {
							nextsym();
						}
						rewind(1);
						m_entries.back().data[opt_key.value()] = capture_until_eol(1024);
					}
				}
				bool eof() {
					bool is_eof = m_offset >= m_file_size;
					if(is_eof) {
						eof_reached();
					}
					return is_eof;
				}
				void eof_reached() {
					m_stop_parse = true;
				}
				bool nextsym() {
					++m_offset;
					return !eof();
				}
				std::string substr(std::size_t size) {
					std::string s;
					auto begin = buf.cbegin() + m_offset;
					if(begin >= buf.cend()) {
						return s;
					}
					auto end = buf.cbegin() + m_offset + size;
					if(end >= buf.cend()) {
						s.resize(std::distance(begin,buf.cend()));
						std::copy(begin,buf.cend(),s.begin());
						return s;
					}
					s.resize(size);
					std::copy(buf.cbegin() + m_offset,buf.cbegin() + m_offset + size,s.begin());
					return s;
				}
				void advance(std::size_t count) {
					m_offset = std::clamp(m_offset + count,m_offset,m_file_size);
				}
				void rewind(int32_t count) {
					m_offset = std::clamp(m_offset - count,(std::size_t)0,(std::size_t)m_file_size);
				}
				std::string capture_until_eol(std::size_t max_len) {
					std::string s;
					std::size_t ctr = 0;
					while(nextsym() && !eof() && current_char() != '\n') {
						s += current_char();
						++ctr;
						if(ctr == max_len) {
							break;
						}
					}
					advance(1);
					return s;
				}
				bool is_lower_match_then_expect(std::string_view look_for,const std::size_t& len, Symbol expect_after_match) {
					m_extra_debug("is_lower_match_then_expect look_for: '" << look_for << "'");
					std::string_view str = substr(len);
					if(ssh::config::util::lower_case_compare(look_for,str)) {
						str = substr(len + 1);
						const char& f = str.back();
						m_debug(" it is a '" << look_for << "' and: '" << str.substr(len) << "'");
						return expect_comparison(f,expect_after_match);
					}
					return false;
				}
				bool is_include_config() {
					return is_lower_match_then_expect(INCLUDE_STRING,INCLUDE_STRING_LENGTH,whitespace);
				}
				bool host() {
					return is_lower_match_then_expect(HOST_STRING,HOST_STRING_LENGTH,whitespace);
				}
				bool match() {
					return is_lower_match_then_expect(MATCH_STRING,MATCH_STRING_LENGTH,whitespace);
				}
				void consume_line() {
					do {
						nextsym();
					} while(!eof() && current_char() != '\n');
				}
				bool accept(Symbol s) {
					if(eof()) {
						return false;
					}
					switch(s) {
						case letter:
							return isalpha(current_char());
						case whitespace:
							return isspace(current_char());
						case comment:
							return current_char() == '#';
						default:
							return false;
					}
				}
				bool expect_comparison(const char& target,const Symbol& s) {
					switch(s) {
						case whitespace:
							return isspace(target);
						case indent:
							m_debug("target: '" << target << "'");
							return target == '\t';
						case alnum:
							return isalnum(target);
						default:
							return false;
					}
				}
				bool expect(Symbol s) {
					if(eof()) {
						return false;
					}
					return expect_comparison(current_char(),s);
				}
		};
	}; // end namespace config
}; // end namespace ssh

#endif
