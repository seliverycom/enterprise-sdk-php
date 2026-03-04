<?php

declare(strict_types=1);

use Selivery\Enterprise\Config;
use Selivery\Enterprise\EnterpriseClient;

require __DIR__ . '/../vendor/autoload.php';

$client = new EnterpriseClient(new Config());

$tokens = $client->auth->generateToken();
print_r($tokens);

// Example: check token validity
if ($tokens->accessToken !== '') {
    $check = $client->auth->checkToken($tokens->accessToken);
    print_r($check);
}
