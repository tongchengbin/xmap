package scanner

var PortRequest = map[int]string{
	80:    "GetRequest",
	110:   "NULL",
	443:   "GetRequest",
	445:   "SMBProgNeg",
	554:   "RTSPRequest",
	25:    "NULL",
	22:    "NULL",
	587:   "NULL",
	3389:  "TerminalServerCookie",
	6379:  "GetRequest",
	8008:  "GetRequest",
	8080:  "GetRequest",
	61616: "NULL",
}
