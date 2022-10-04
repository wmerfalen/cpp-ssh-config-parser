#include "../lib/parser.hpp"
#include <fstream>

#define GET_STATUS(A) std::get<A>(parse_status)

namespace ssh_config_parser_tests {
	std::string to_string(const std::tuple<bool,std::size_t,std::string,int16_t>& t) {
		std::string s = "{";
		if(std::get<0>(t)) {
			s += "true,";
		} else {
			s += "false,";
		}
		s += std::to_string(std::get<1>(t)) + ",";
		s += std::get<2>(t);
		s += ",";
		s += std::to_string(std::get<3>(t));
		s += "}";
		return s;
	}
	std::string blue(std::string msg) {
		return std::string("\x1B[35m") + msg + "\033[0m";
	}
	std::string red(std::string msg) {
		return std::string("\x1B[31m") + msg + "\033[0m";
	}
	std::string yellow(std::string msg) {
		return std::string("\x1B[34m") + msg + "\033[0m";
	}
	std::string green(std::string msg) {
		return std::string("\x1B[32m") + msg + "\033[0m";
	}
	void dump_lines(const std::vector<std::string> issues) {
		for(const auto& i : issues) {
			std::cerr << red("\t[issue]: ") << red(i) << "\n";
		}
	}
#define TEST_PASS() return TEST_PASS_ACTUAL(__FUNCTION__);
#define TEST_ENTRY() std::cout << blue("Running: ") << blue(__FUNCTION__) << "\n";
	bool TEST_PASS_ACTUAL(std::string func) {
		std::cout << green("\t[TEST_PASSED]: ") << green(func) << "\n";
		return true;
	}
#define TEST_FAIL(A) return TEST_FAIL_ACTUAL(__FUNCTION__,A);

	bool TEST_FAIL_ACTUAL(std::string test, std::vector<std::string> issues) {
		std::cerr << red("\t[TEST_FAILED]:") << yellow(test) << red(" FAILED!") << "\n";
		for(const auto i : issues) {
			std::cerr << red("[issue]: ") << red(i) << "\n";
		}
		return false;
	}
	template <typename T>
	std::vector<char> vectorize(const T& b) {
		std::vector<char> v;
		std::copy(b.begin(),b.end(),std::back_inserter(v));
		return v;
	}
	std::vector<std::string> vectorize_str(std::initializer_list<std::string> i) {
		return i;
	}
	using namespace ssh::config;
	bool test_empty_file_creates_no_entries() {
		TEST_ENTRY();
		std::vector<char> empty_file;
		parser p(empty_file);
		std::tuple<bool,std::size_t,std::string,int16_t> parsed = p.start_parse();
		if(!std::get<0>(parsed)) {
			TEST_FAIL(vectorize_str({
				"Expected to get a successful parse but got false",
				to_string(parsed),
			}));
		}
		TEST_PASS();
	};
	bool test_comments_before_host_safely_ignored() {
		TEST_ENTRY();
		std::string buffer = "#\n"
		    "# This is a comment\n"
		    "Host github.com\n"
		    "\tPubkeyAuthentication no\n"
		    ;
		parser p(vectorize(buffer));
		std::tuple<bool,std::size_t,std::string,int16_t> parsed = p.start_parse();
		if(!std::get<0>(parsed)) {
			TEST_FAIL(vectorize_str({
				"Expected to get a successful parse but got false",
				to_string(parsed),
			}));
		}
		TEST_PASS();
	}

	bool test_comments_in_indented_lines_are_ignored() {
		TEST_ENTRY();
		std::string buffer =
		    "Host github.com\n"
		    "\tPubkeyAuthentication no\n"
		    "\t#PasswordAuthentication yes\n"
		    "\n"
		    ;
		parser p(vectorize(buffer));
		std::tuple<bool,std::size_t,std::string,int16_t> parsed = p.start_parse();
		if(!std::get<0>(parsed)) {
			TEST_FAIL(vectorize_str({
				"Expected to get a successful parse but got false",
				to_string(parsed),
			}));
		}
		std::vector<entry> entries = p.get_entries();
		if(entries.size() == 0) {
			TEST_FAIL(vectorize_str({
				"Parsed entries is zero"
			}));
		}
		TEST_PASS();
	}
	bool test_negated_rules_apply_to_rules() {
		TEST_ENTRY();
		std::string buffer =
		    "Host !router\n"
		    "\tBindAddress 192.168.34.49\n"
		    "\n"
		    "Host github.com\n"
		    "\tPasswordAuthentication yes\n"
		    ;
		parser p(vectorize(buffer));
		std::tuple<bool,std::size_t,std::string,int16_t> parsed = p.start_parse();
		if(!std::get<0>(parsed)) {
			TEST_FAIL(vectorize_str({
				"Expected to get a successful parse but got false",
				to_string(parsed),
			}));
		}
		std::vector<entry> entries = p.get_entries();
		if(entries.size() == 0) {
			TEST_FAIL(vectorize_str({
				"Parsed entries is zero"
			}));
		}
		entry& router = entries[0];
		if(router.hosts[0].get_name().compare("router") == 0) {
			TEST_FAIL(vectorize_str({
				"Expected 'router' as first host in first entry. Instead, we got:",
				std::string(router.hosts[0].get_name()),
			})
			);
		}
		if(router.hosts[0].is_negated() == false) {
			TEST_FAIL(vectorize_str({
				"router rule not negated"
			}));
		}
		TEST_PASS();
	}
	void run_all() {
		test_empty_file_creates_no_entries();
		test_comments_before_host_safely_ignored();
		test_comments_in_indented_lines_are_ignored();
		test_negated_rules_apply_to_rules();
	}
};

int main(int argc,char** argv) {
	ssh_config_parser_tests::run_all();
	return 0;
}

