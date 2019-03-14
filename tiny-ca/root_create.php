<?php

if (!in_array('--delete-old-ca', $argv) && file_exists("certs/root.crt")) {
	die("Are you sure? You already have a root CA inside the certs folder. Please re-run with --delete-old-ca if you want to create a new root CA.\nLeaving current certificates untouched!\n");
}

echo "Creating root CA in certs folder...\n";

$config = array("digest_alg" => "sha256", 'config' => './openssl.cnf', "x509_extensions" => "v3_ca");

$dn = array(
		"countryName" => "SE",
		"stateOrProvinceName" => "Stockholm",
		"localityName" => "Stockholm",
		"organizationName" => "Caprioli",
		"organizationalUnitName" => "Caprioli",
		"commonName" => "Caprioli Root Certificate Authority",
		"emailAddress" => "peter@caprioli.se",
);

$root_key = openssl_pkey_new(array('private_key_bits' => 4096));
$root_csr = openssl_csr_new($dn, $root_key, $config);
$root_cert = openssl_csr_sign($root_csr, NULL, $root_key, 365*50, $config, 1337);

$rkey = $rcert = "";
openssl_x509_export($root_cert, $rcert);
openssl_pkey_export($root_key, $rkey);

file_put_contents("certs/root.key", $rkey);
file_put_contents("certs/root.crt", $rcert);

?>
