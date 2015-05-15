# vtdomain
check domain status via virustotal and save to sqlite

the benefit:

+ split the result into each column;
+ easy search with sqlite when you have large url;
+ easy to extension with read url from file or sqlite;
+ support multiple virustotal api key;


### install

1. need to add you api key to apikey=["key1", "key2", "key3"]
2. add your test domain, check("domain") in the main function;
3. python vtdomain.py;
4. sqlite3 m_domain.db;