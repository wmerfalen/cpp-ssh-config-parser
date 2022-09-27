#include "../lib/parser.hpp"

#define GET_STATUS(A) std::get<A>(parse_status)

int main(int argc,char** argv) {
	std::string filename = "ssh.config";
	ssh::config::parser p(filename);
	// No sense in keeping the file descriptor open as the parser will
	// never need it once it's opened the file (which is what p(filename) did)
	//
	p.close();
	auto parse_status = p.start_parse();
	if(!GET_STATUS(0)) {
		std::cerr << "Error: '" << GET_STATUS(2) << "'\n";
		exit(1);
	}
	std::cout << "[info]: '" << GET_STATUS(2) << "' opened file successfully.\n";
	p.report();
	return 0;
}

