<?php
/*

v1.0.0 20151129 ptudor.ptudor.net

This PHP script is an interface to UNIX commands for web browsers.

At its essence it just runs a command with a string and returns plain text.
Along the way, it enforces primitive quotas to limit abuse,
converts unicode to ASCII, and caches results in redis for eight hours.
The result is gzipped before being stored and returned as-is when possible.

The script has two modes: search and results. Search is used, 
often with an argument of "domain" or "string", when a POST or GET
is issued against the path /cgi-bin/cowsay. Results is used as the
target of a location redirect after the CGI POST to display data 
in response to a request like /get/cowsay/example.txt.
Refer to the included Apache rewrite rules for those paths.

*/

// start the counter
$start_time = microtime(true); 

unset($debug);

if (file_exists("config.php")) {
	require("config.php");
   } else {
	require("config-goddard.php");
}

/*
 * In theory, significant errors are reported via /dev/log or smtp or whatever
 */
function notify_about_error($actiontaken,$errormessage) {
	// actiontaken is either continue or exit
	// errormessage is generally a string
	openlog('goddard-cache', LOG_NDELAY, LOG_USER);
	syslog(LOG_NOTICE, "Experienced error of type: " . $actiontaken);
	syslog(LOG_ERR, "Message: " . $errormessage);
	error_log($errormessage, 0);
	closelog();
	return 0;
}

function sha256($string) {
	// a drop-in for "md5()" habits
	$algo = 'sha256';
	return hash($algo, $string);
	}

class MyDB extends SQLite3 {

    function __construct()
    {
        $this->open('/tmp/goddard-sqlite3.db',SQLITE3_OPEN_READWRITE|SQLITE3_OPEN_CREATE);
    }

    public function insert_research($timestamp,$input) {                                        
        $query = <<<EOD
          CREATE TABLE IF NOT EXISTS research (                                                 
            input STRING,                                                                       
            timestamp INTEGER)                                                                  
EOD;
        $this->exec($query) or die('Create table failed');                                      

        $statement = $this->prepare('INSERT INTO research VALUES (:in, :ti);');                 
        $statement->bindValue(':in', $input);                                                   
        $statement->bindValue(':ti', $timestamp);                                               
        $result = $statement->execute();                                                        
        return 0;                                                                               
    }

    // 100% untested. certain to fail.
    public function select_research() {                                                         
        $statement = $this->exec('SELECT input,count(*) FROM research GROUP BY input;');        
        return $statement;                                                                 
        $statement = $this->prepare('SELECT input,count(*) FROM research GROUP BY input;');
        $result = $statement->execute();                                                   
        return $result;                                                                    
    }                                                                                      

}

class MyRedis {
/*
 * Core redis functionality, connecting to the daemon after the new() worked.
 */
    // password for redis. This default updated everytime by startup script.
    const REDIS_AUTH_KEY = 'oce-6EA-zd2'; // "oh"ce-6EA-zd2

    private function getRedisAuthKey() {
        return self::REDIS_AUTH_KEY;
    }

    public function connect_to_redis() {
	// this requires redis.so, please have it installed
	global $redis, $debug;
	// prefer persistent connection
	$redis->pconnect('127.0.0.1'); // port 6379 default

	// if redis dies, this will catch it
	try {
		// attempt to authenticate
                $redis->auth($this->getRedisAuthKey());                         
	} catch (Exception $e) {
		//echo 'Caught exception: ',  $e->getMessage(), "\n";
		header("X-Exception-Catch: " . $e->getMessage());
		notify_about_error("exit",$e->getMessage());
		echo "Unable to complete your request. Sorry about that.\n";
		exit();
	} finally {
		//echo "Probably because redis-server went away unexpectedly.\n";
	}

	try {
		// switch to database three
		$redis->select(REDIS_DB);
	} catch (Exception $e) {
		header("X-Exception-Catch: " . $e->getMessage());
		notify_about_error("exit",$e->getMessage());
		echo "Unable to complete your request. So sorry about that.\n";
		exit();
	} finally {
		//echo "Probably because redis-server failed auth.\n";
	}

	// bump the connections
	$redis->incr('hitcount_connect');
	if ($debug) {
		$counter_connections = $redis->get('hitcount_connect');
		header("X-Goddard-Hitcount: $counter_connections");
		// how many objects?
		$counter_dbsize = $redis->dbSize();
		header("X-Goddard-dbSize: $counter_dbsize");
	}
	return 0;
    }
} // end class

class MyQuota {

    const QUOTA_TIMEOUT = 120; // in seconds

    private function getTimeoutValue() {
	return self::QUOTA_TIMEOUT;
    }

/*
 * This quick statement increments the quota key
 */
    private function incr_quota_in_redis($key) {
	global $redis, $debug;
	// do things nice with a statement
	$ret = $redis->multi()
		->incr($key, '1')
		->expire($key,$this->getTimeoutValue())
		->exec();
	return $ret;
    }

/*
 * Here we fetch the value of the quota key
 */
    private function get_quota_from_redis($key) {
	global $redis, $debug;
	$quota = $redis->get($key);
	if ($debug) header("X-Goddard-Quota: $quota"); 
	return $quota;
    }

/*
 * This computes the key used for the quota, 
 * increments the quota, and returns its new value
 */
    public function get_quota() {
	global $redis, $sessid, $debug;
	// php session is useless for throttling, client can just not
	// send a cookie. but useful for later expanding restrictions maybe.
	$sess = $sessid ; //session_id();
	$this->incr_quota_in_redis($sess);
	if ($debug) header("X-Goddard-Quota-Sess1: $sess");

	// And a User-Agent could be null. Probably not, and the Remote Address
	// is hopefully something other than 127.0.0.1 or the ssl proxy address.
	// if it is null, who cares, default bucket. set up mod_remoteip.
	$sess2 = sha256($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . HASH_SECRET );
	$this->incr_quota_in_redis($sess2);
	if ($debug) header("X-Goddard-Quota-Sess2: $sess2");

	return $this->get_quota_from_redis($sess2);
    }
} // end class

class MyCookie {

    const COOKIE_LIFETIME = 86400; // in seconds

    private function getLifetimeValue() {
	return self::COOKIE_LIFETIME;
    }
/*
 * A single install could have a variety of names.
 * Set the cookie based on who the client thinks we are.
 * Extract the Host: header for use in the cookie
 */
    public function get_virtual_host_name() {
	if(array_key_exists('HTTP_HOST', $_SERVER)){
		$host = $_SERVER['HTTP_HOST'];
		// if there's a port number pull it off
		$host = preg_replace('/:\d+$/', '', $host);
		return trim($host);
	} elseif (array_key_exists('SERVER_NAME', $_SERVER)){
		return $_SERVER['SERVER_NAME'];
	}
	return "example.com";
    }

/*
 * This constructs the cookie options and begins the session
 */
    public function set_sesscookie() {
	session_set_cookie_params( 
		$this->getLifetimeValue(),//lifetime in seconds
		'/',			//path in url
		$this->get_virtual_host_name(),// host like ".example.com"
		0, 			// secure flag
		1			// httponly flag
	); 

	// four possible modes, no-cache default, this is almost public.
	session_cache_limiter('private_no_expire');
	session_start([
		'cookie_lifetime' => 86400,
		// read and close is when there are no session updates to make
		'read_and_close'  => true,
	]);
	return session_id();
    }

    public function get_sesscookie() {
	return session_id();
    }
} //end class


class StoredRecord {

    const CACHE_EXPIRE = 28800; // in seconds

    private function getExpireValue() {
	return self::CACHE_EXPIRE;
    }
/*
 * push the output from stdout into redis
 */
    private function set_record_in_redis($inputhash, $shell_command_output) {
	global $redis, $debug;
	if ($debug) header("X-Goddard-Set: $inputhash");
	// using deflate (gzencode is zlib for browsers) to mask newlines and save ram
	$shell_command_output = gzencode($shell_command_output);
	// set the key, value, and expiration in seconds, here eight hours
	return $redis->set($inputhash, $shell_command_output, Array('ex'=>self::CACHE_EXPIRE));
    }

    private function set_timestamp_in_redis($inputhash) {
	global $redis, $debug;
	// add in a timestamp too for etag/last-modified
	return $redis->set($inputhash . "_ts", time(), Array('ex'=>self::CACHE_EXPIRE));
    }

/*
 * cross your fingers for the xn-- escaping and run command in shell.
 * be careful of solutions other than shell_exec that only return the last line.
 */
    public function get_string_from_shell($inputhash, $string, $adjustedname) {
	global $redis, $debug;
	$redis->incr('hitcount_fresh');
	if ($debug) {
		$counter_fresh = $redis->get('hitcount_fresh');
		header("X-Goddard-Hitcount-Fresh: $counter_fresh");
	}
	// hoping for the best...
	// "escape" is to prevent for example "?domain=;echo%20$PATH;cat%20index.php"
	// "escapeshellarg() adds single quotes around a string and quotes/escapes any existing single quotes "
	// the variant with cmd() adds backslashes so not using it.
	$exec = EXTERNAL_BINARY . " " . escapeshellarg($adjustedname); 
	// this try/catch doesn't work. chmod 644 /usr/bin/ls
	// will exit 126 but this is happy to return a blank page
	try {
		$shell_command_output = shell_exec($exec);
	} catch (Exception $e) {
		//echo 'Caught exception: ',  $e->getMessage(), "\n";
		header("X-Exception-Catch: " . $e->getMessage());
		notify_about_error("exit",$e->getMessage());
		echo "Difficulties serving your request. Sorry about that.\n";
		exit();
	} finally {
		//echo "Problems with the binary? Weird.\n";
	}

/*
	// testing. try to find the verisign referral and re-run
	if ( (substr($string, -4) === ".com") && (!$infinite_loop) ) {
		$infinite_loop = true;
		// magic. http://stackoverflow.com/questions/14675452/find-whole-line-that-contains-word-with-php-regular-expressions
		echo $shell_command_output;
		$pattern = '/^.*Whois Server.*$/m';
		$matches = array();
		preg_match($pattern, $shell_command_output, $matches);
		header("X-dotcom: " . $matches[0]);
		print_r($matches); exit();
		$whois_server = "-h " . $matches[0];
	}
*/

	// check for any response at all
	if (strlen($shell_command_output) < 10 ) { // arbitrarily selected "too small" length.
		echo "Received a bad response. Exiting.\n"; // some weird problem with binary?
		exit();
	}
	// save the result into redis
	return $this->set_record_in_redis($inputhash, $shell_command_output);
    }

/*
 * The timestamp the shell object was fetched is stored in blah_ts
 * and is used in the ETag and last-modified.
 */
    public function get_timestamp_from_redis($inputhash) {
	global $redis, $debug;
	// first let's find an existing timestamp
	$ts = $redis->get($inputhash . "_ts");
	// if there isn't one, create it.
	if (empty($ts)) {
		$this->set_timestamp_in_redis($inputhash);
		return $redis->get($inputhash . "_ts");
	} 
	// if there was one, send it
	return $ts;
    }

/*
 * Fetching the cached, compressed stdout object by its hashed key
 */
    public function get_record_from_redis($userinput_hash) {
	global $redis, $debug;
	$redis->incr('hitcount_cached');
	if ($debug) {
		$counter_cached = $redis->get('hitcount_cached');
		header("X-Goddard-Hitcount-Cached: $counter_cached");
	}
	// still needs gzdecode this point; browser optimized
	return $redis->get($userinput_hash);
    }
} //end class

class RdapRecord {
/*
 * for-future-release
 */
    function get_rdap_from_internet($string) {
	$url = "http://rdap.arin.net/bootstrap/ip/192.168.0.0/16";
        $ch = curl_init(); 
        curl_setopt($ch, CURLOPT_URL, $url); 
        $fetch = curl_exec($ch); 
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE); 
        curl_close($ch); 
	$last_url = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
    }
} // end class

class MyHTTP {
/*
 * return data. if client supports gzip, send it raw otherwise gunzip first.
 */
public function send_data_to_browser($data) {
	global $start_time, $debug;
	// since the data is already gzipped in redis, send it out that way
	//$HTTP_ACCEPT_ENCODING = $_SERVER["HTTP_ACCEPT_ENCODING"]; 
        $time_taken = microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];
        if ($debug) header("X-Goddard-Runtime2: $time_taken"); 
	if ($debug) header("X-Goddard-Runtime: " . number_format(microtime(true) - $start_time, 4) );
	if (strpos($this->get_header_accept_encoding(),'gzip') !== false )  {
        	header("Vary: Accept-Encoding");
        	header("Content-Encoding: gzip");
		header("Content-Length: " . strlen($data));
		echo $data;
	} else {
		// but if it's me telnetting, send the uncompressed plain text
		echo gzdecode($data);
	}
	return 0;
}

    private function get_header_accept_encoding() {
	if(array_key_exists('HTTP_ACCEPT_ENCODING', $_SERVER)){
		return trim($_SERVER["HTTP_ACCEPT_ENCODING"]);
	}
	return 0;
    }

    private function get_header_if_none_match() {
	if(array_key_exists('HTTP_IF_NONE_MATCH', $_SERVER)){
		return trim($_SERVER["HTTP_IF_NONE_MATCH"]);
	}
	return 0;
    }

    private function get_header_if_modified_since() {
	if(array_key_exists('HTTP_IF_MODIFIED_SINCE', $_SERVER)){
		return trim($_SERVER["HTTP_IF_MODIFIED_SINCE"]);
	}
	return 0;
    }

    public function get_header_host() {
	if(array_key_exists('HTTP_HOST', $_SERVER)){
		return trim($_SERVER['HTTP_HOST']);
	} elseif (array_key_exists('SERVER_NAME', $_SERVER)){
		return trim($_SERVER['SERVER_NAME']);
	}
	return "localhost";
}

    public function respond_with_redirect($code, $url) {
	// trying for schema independence here. hasn't failed yet.
	$url = "//" . $this->get_header_host() . $url;
	http_response_code($code); // "moved temp"
	header("Location: " . $url );
	echo "Document moved: " . $url ;
	exit();
    }

    public function get_value_etag($timestamp, $inputhash) {
	return sha256($timestamp . $inputhash . HASH_SECRET);
    }

    public function get_value_last_modified($timestamp) {
	return gmdate('D, d M Y H:i:s', $timestamp).' GMT';
    }

    // ETag and Last-Modified
    public function respond_not_modified($timestamp, $inputhash) {
	if ( $this->get_header_if_none_match() === $this->get_value_etag($timestamp, $inputhash) ) {
	   http_response_code(304); // "304 not modified"
  	   exit();
 	} elseif ( strtotime($this->get_header_if_modified_since()) >= $timestamp ) {
	   http_response_code(304); // "304 not modified"
  	   exit();
	}
	return 0;
    }

/*
 * this sends an error message of some kind to the browser
 */
    public function respond_with_error($errorcode,$text) {
	notify_about_error("exit",$text);
	http_response_code($errorcode); // "service unavailable"
	header("Retry-After: 120"); // "come back in 120 seconds" 
	echo $text;
	exit();
    }
} // end class
	
class MyTextInputTools {
/*
 * just avoiding using user input as a key by making a hash
 */
    public function get_userinput_hash($string) {
	global $debug;
	$algo = 'sha256';
	$inputhash = hash($algo, $string . HASH_SECRET);
	if ($debug) header("X-Goddard-Input-Hash: $inputhash");
	return $inputhash;
    }

    public function get_userinput_name($string) {
	global $debug;
	$string = idn_to_ascii($string);
	if ($debug) header("X-Goddard-Input-String: $string");
	return $string;
    }

   public function get_userinput_adjusted($string) {
	// gonna need logic here for specific tlds and specific whois options
	if  (substr($string, -4) === ".com") {
		// fix dotcom a little
		// ugh but then referrals break. ugh.
		// I suppose Some info is better than No info
		// maybe change the dotcom server to one sans referal
		$string = "domain " . $string ;
		return $string;
	}
	return $string;
    }
}// end class


/*
 * main program
 */

$myhttp = new MyHTTP();

// check to see that the redis.so module is installed and active
$cache_unavailable = false ;
try {
	$redis = new Redis();
} catch (Exception $e) {
	//echo 'Caught exception: ',  $e->getMessage(), "\n";
	notify_about_error("continue",$e->getMessage());
	header("X-Exception-Catch: " . $e->getMessage());
	$cache_unavailable = true ;
} finally {
	//echo "Probably because redis.so isn't enabled.\n";
}

// unavailable is set by the first Try for redis.so
if ($cache_unavailable) {
	$myhttp->respond_with_error("500", "Unable to complete the request. Sorry about that.\n");
} else {
	$myredis = new MyRedis();
	$myredis->connect_to_redis();
}

// check just in case the session was initialized externally
if (session_status() == PHP_SESSION_NONE) {
	$mycookie = new MyCookie();
	$sessid = $mycookie->set_sesscookie();
	if ($debug) header("X-Goddard-Session: $sessid");
}

$myquota = new MyQuota();
$quota = $myquota->get_quota();
// double the actual max because each hit is counted twice with post-redirect-get
if ( ($quota === NULL) || ($quota > QUOTA_MAX * 2) ) {
	if ($debug) header("X-Goddard-Runtime: " . number_format(microtime(true) - $start_time, 4) );
	$myhttp->respond_with_error("503", "Rate limited. Please try again in two minutes.\n");
}

$myinputtools = new MyTextInputTools();
// php sends an "undefined index" to the logs if this is unset
$external_userinput_name = $_REQUEST[URL_SEARCH_KEY] ;
// or set a failsafe.
if (empty($external_userinput_name)) { 
	$external_userinput_name = DEFAULT_STRING_FOR_SEARCH;
}

$userinput_name = $myinputtools->get_userinput_name($external_userinput_name);
$userinput_adjusted = $myinputtools->get_userinput_adjusted($userinput_name);
// ignore the "adjusted" for now.
$userinput_adjusted = $userinput_name;

// this is a sha256 hash of the input string used as a key for redis
$userinput_hash = $myinputtools->get_userinput_hash($userinput_name);

// in case expose_php isn't set to off
if (function_exists('header_remove')) {
    if (!$debug) header_remove('X-Powered-By');
}

// don't let the response to the client become html
header("Content-Type: text/plain; charset=UTF-8");

// if you want to log each query temporarily into sqlite3, this is a starting place.
// not well tested.
if ($debug) {
	$db = new MyDB();
	$research = $db->insert_research(time(),$userinput_name);
}

// this section handles the post/redirect/get.
// Apache makes goddard-cache.php look like:
// Post: /cgi-bin/cowsay?mode=search&string=example
// Get: /get/cowsay/example.txt
$external_mode_results = $_REQUEST['mode'] ;
if (!empty($external_mode_results)) {
  switch ($external_mode_results) {
    case "search":
        //$url = "goddard-cache.php?mode=results&searchstring=". $userinput_name;
        $url = URL_BASE . $userinput_name . ".txt";
	// 303 because we're not stuck with http/1.0 anymore
	$redirect = $myhttp->respond_with_redirect(303, $url);
        break;
    case "results":
	// here we trust what we were given by the redirect or received and keep running
        break;
    default:
	// it really should match either of those two and nothing else.
    	$myhttp->respond_with_error("503", "Request looks strange.\n");
	break;
  } //end switch
  } else {
    // didn't get a "mode" in the Post (or Rewrite). Very odd.
    $myhttp->respond_with_error("503", "Request appears malformed.\n");
}

$storedrecord = new StoredRecord();
// set an accurate Last-Modified header
$timestamp_for_modified = $storedrecord->get_timestamp_from_redis($userinput_hash);

if ($debug) header("X-Goddard-Timestamp: $timestamp_for_modified");
// if we have a timestamp in redis and it's a number,
if ($timestamp_for_modified > 1) {
	// it's possible the client has it cached. check to see if a 304 is okay
	// this function will exit if successful.
	$test_ts = $myhttp->respond_not_modified($timestamp_for_modified, $userinput_hash);
	// try to send a timestamp associated with a cached object
	header('Last-Modified: '. $myhttp->get_value_last_modified($timestamp_for_modified), true, 200);
	// build an etag from the timestamp and input hash
	header('ETag: ' . $myhttp->get_value_etag($timestamp_for_modified, $userinput_hash));
} else {
	// prevent Apache from serving the date of the php file itself
	// "true" replaces previously set headers.
	header('Last-Modified: '. $myhttp->get_value_last_modified(time()), true, 200);
}

// with everything set up, try to return a cached response
$redis_response = $storedrecord->get_record_from_redis($userinput_hash);
if ($redis_response) {
	// cool, found a cached response. send it.
	$myhttp->send_data_to_browser($redis_response);
    } else {
	$origin_fetch = $storedrecord->get_string_from_shell($userinput_hash, $userinput_name, $userinput_adjusted);
	if ($origin_fetch) { 
		$redis_response = $storedrecord->get_record_from_redis($userinput_hash);
		$myhttp->send_data_to_browser($redis_response);
	} else {
		$myhttp->respond_with_error("503", "Something unexpected happened. Sorry about that.\n");
	}
}

exit();
?>
