# SSH Config Parser
A header only ssh config parser library.

# Usage
``` c++
#include "src/lib/parser.hpp"

int main(int argc,char** argv){
	if(argc < 2){
		std::cerr << "Usage: " << argv[0] << " <FILE>\n";
		return 1;
	}
	std::string file = argv[1];
	ssh::config::parser p(file);
	p.start_parse();
	p.report();
	return 0;
}
```

# TODO
- Handle Match/Host entries when applying to multiple sections

# Version
v1.1.0
