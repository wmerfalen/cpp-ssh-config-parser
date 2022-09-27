#include "../lib/parser.hpp"

int main(int argc,char** argv) {
	std::string filename = "ssh.config";
	ssh::config::parser p(filename);
	p.start_parse();
	p.report();
	return 0;
}

