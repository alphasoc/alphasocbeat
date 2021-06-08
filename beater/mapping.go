package beater

// eventFields is map of json event fields names with matching elastic index field name value
var eventFields = map[string]string{
	// Event header
	"srcHost": "source.address",
	"srcIP":   "source.ip",
	"srcMac":  "source.mac",
	"srcPort": "source.port",
	"srcUser": "alphasoc.event.src.user",
	"srcID":   "alphasoc.event.src.id",

	// DNS
	"query": "alphasoc.event.query",
	"qtype": "dns.question.type",

	// HTTP
	"url":         "url.original",
	"method":      "alphasoc.event.method",
	"status":      "alphasoc.event.status",
	"contentType": "alphasoc.event.content_type",
	"referrer":    "alphasoc.event.referrer",
	"userAgent":   "alphasoc.event.user_agent",

	// IP
	"destIP":   "destination.ip",
	"destPort": "destination.port",
	"bytesIn":  "destination.bytes",
	"bytesOut": "source.bytes",
	"proto":    "network.transport",
	"duration": "event.duration",

	"app":    "network.protocol",
	"action": "alphasoc.event.action",

	// TLS
	"ja3":       "alphasoc.event.ja3",
	"ja3s":      "alphasoc.event.ja3s",
	"certHash":  "alphasoc.event.cert_hash",
	"issuer":    "alphasoc.event.issuer",
	"subject":   "alphasoc.event.subject",
	"validFrom": "alphasoc.event.valid_from",
	"validTo":   "alphasoc.event.valid_to",
}
