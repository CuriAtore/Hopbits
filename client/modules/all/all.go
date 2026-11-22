// Package all lists the modules compiled into the node client. Adding a
// module to the client is one line here.
package all

import (
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/dnsquery"
	"github.com/hopbits/client/modules/httpcheck"
	"github.com/hopbits/client/modules/icmpping"
	"github.com/hopbits/client/modules/mtr"
	"github.com/hopbits/client/modules/tcpconnect"
	"github.com/hopbits/client/modules/traceroute"
)

// Default returns a fresh instance of every compiled module, in
// registration order.
func Default() []module.Module {
	return []module.Module{
		httpcheck.New(),
		tcpconnect.New(),
		icmpping.New(),
		dnsquery.New(),
		traceroute.New(),
		mtr.New(),
	}
}
