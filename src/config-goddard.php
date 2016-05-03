<?php

$debug=false;

// copy me to config.php if changing defaults

//define ('EXTERNAL_BINARY','/usr/bin/whois');
//define ('EXTERNAL_BINARY','/usr/bin/cowsay');
define ('EXTERNAL_BINARY','/usr/bin/cowsay -f stegosaurus');

define ('DEFAULT_STRING_FOR_SEARCH','default-example-value');

// default is 20 requests per 120 seconds.
// this quota is later doubled to account for normal post/get
define('QUOTA_MAX', '20'); // requests per QUOTA_TIMEOUT seconds

// redis database
define('REDIS_DB','3'); // 1 is used by sessions
// just some entropy in userinput_hash. Safely expire everything by changing a character.
define('HASH_SECRET','whggjtblv1');

// url used in post-redirect-get
// https://example.com/cgi/search?key=value
//define('URL_BASE','/cgi/');
//define('URL_SEARCH_KEY','search');
// https://example.com/get/goddard-search/goddard-search?key=value
define('URL_BASE','/get/goddard-search/');
define('URL_SEARCH_KEY','goddard-search');

setlocale(LC_CTYPE, "en_US.UTF-8");
ini_set('date.timezone', 'UTC');

?>
