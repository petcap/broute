<?php

$host = '192.168.43.195';
$port = 1337;
$timeout = 2;

$context = stream_context_create(
    [ 'ssl'=> [ 'local_cert'=> "./r1.pem", "crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT, "cafile" => "root.crt" ] ]
);

stream_context_set_option($context, 'ssl', 'allow_self_signed', false);
stream_context_set_option($context, 'ssl', 'verify_peer', true);
stream_context_set_option($context, 'ssl', 'local_cert', "./r2.pem");
stream_context_set_option($context, 'ssl', 'cafile', "./root.crt");
stream_context_set_option($context, 'ssl', 'verify_peer_name', false);

if ($socket = stream_socket_client('tls://'.$host.':'.$port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context)) {
    $meta = stream_get_meta_data($socket);

    print_r( $meta );

    fwrite($socket, "Hello, World!\n");
    echo stream_socket_recvfrom($socket,8192);
    fclose($socket);
} else {
   echo "ERROR: $errno - $errstr\n";
}
