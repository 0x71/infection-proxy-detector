<?php
// Copyright (C) 2015-2016  Nils Rogmann.
//  This file is part of infection-proxy detector.
//  See the file 'docs/LICENSE' for copying permission.

$user = "foobar";
$password = "foobar";


// Most of the code ist taken from https://gist.github.com/dperini/729294

const RX_LINK_ALL = '#
    (?<=^|\s)
    (?:(?:https?|ftp)://)?
    (?:\S+(?::\S*)?@)?
    (?:
        (?!10(?:\.\d{1,3}){3})
        (?!127(?:\.\d{1,3}){3})
        (?!169\.254(?:\.\d{1,3}){2})
        (?!192\.168(?:\.\d{1,3}){2})
        (?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})
        (?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])
        (?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))
    |
        (?:[a-z\x{00a1}-\x{ffff}0-9]+(?:-[a-z\x{00a1}-\x{ffff}0-9]+)*)
        (?:\.[a-z\x{00a1}-\x{ffff}0-9]+(?:-[a-z\x{00a1}-\x{ffff}0-9]+)*)*
        (?:\.(?:[a-z\x{00a1}-\x{ffff}]{2,}))
    )
    (?::\d{2,5})?
    (?:/\S*)?
    (?=\s|$)
#ux';

// Taken from http://4rapiddev.com/php/download-image-or-file-from-url/
function download_remote_file_with_fopen($file_url, $folder)
	{
		$in=    fopen($file_url, "rb");
		$out=   fopen($folder.basename($file_url), "wb");

		while ($chunk = fread($in,8192))
		{
			fwrite($out, $chunk, 8192);
		}

		fclose($in);
		fclose($out);
	}

////////

if (isset($_POST["user"]) && !empty($_POST["user"])) {
	if (isset($_POST["p"]) && !empty($_POST["p"])) {
		if ($user == $_POST["user"] && $password == $_POST["p"]) {
			if (isset($_POST["url"]) && !empty($_POST["url"])) {
				// echo "URL set.</br>";
				$url = $_POST["url"];
				$url = trim($url, '!"#$%&\'()*+,-./@:;<=>[\\]^_`{|}~');

				if(preg_match(RX_LINK_ALL,$url)) {
					download_remote_file_with_fopen($url,"/tmp/");

					// Hash
					echo hash_file('sha256',"/tmp/".basename($url));
					unlink("/tmp/".basename($url));
				} else {
					echo "invalid url.";
				}
			}
        	}
    	} else {
		echo "invalid password";
	}
} else {
	echo "invalid user";
}

?>
