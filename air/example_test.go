package air

import "fmt"

func ExampleDNSRecords() {
	recs, _ := DNSRecords("acme.example.com", "100.64.0.2", 9600, "gateway.netbird.cloud")
	for _, r := range recs {
		fmt.Println(r)
	}
	// Output:
	// _catalog._agents.acme.example.com. 300 IN TXT "v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json"
	// _air._tcp.acme.example.com. 300 IN SRV 0 5 9600 gateway.netbird.cloud.
}

func ExampleParseCatalogTXT() {
	url, ok := ParseCatalogTXT(`v=ard1; catalog=http://100.64.0.2:9600/.well-known/ai-catalog.json`)
	fmt.Println(ok, url)
	// Output:
	// true http://100.64.0.2:9600/.well-known/ai-catalog.json
}

func ExampleCatalog() {
	c := NewCatalog("meshmcp", "1.0", "gw.mesh").
		Add(CatalogEntry{Name: "fs", Address: "100.64.0.2:9101", Transport: TransportStdio, Steerable: true})
	fmt.Println(c.Names())
	e, _ := c.Entry("fs")
	fmt.Println(e.Address, "steerable:", len(c.Steerable()))
	// Output:
	// [fs]
	// 100.64.0.2:9101 steerable: 1
}

func ExampleSteerEnvelope_Validate() {
	fmt.Println(Task("read_file", nil).Validate())
	fmt.Println(SteerEnvelope{Type: "task"}.Validate())
	// Output:
	// <nil>
	// steer type "task" requires a tool
}

func ExampleParseTarget() {
	t, _ := ParseTarget("task:9f2a")
	fmt.Printf("%s / %s\n", t.Kind, t.Value)
	// Output:
	// task / 9f2a
}

func ExampleParseWorkflow() {
	wf, _ := ParseWorkflow([]byte("name: demo\nsteps:\n  - launch: { role: reader, gateway: g:1 }\n  - call: { target: g:1, tool: summarize }\n"))
	for _, k := range wf.Plan() {
		fmt.Println(k)
	}
	// Output:
	// launch reader
	// call summarize@g:1
}
