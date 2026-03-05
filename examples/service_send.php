<?php

declare(strict_types=1);

use Selivery\Enterprise\Config;
use Selivery\Enterprise\EnterpriseClient;

require __DIR__ . '/../vendor/autoload.php';

$secret = getenv('SELIVERY_SECRET') ?: '';
$client = new EnterpriseClient(new Config(secret: $secret));

$response = $client->service->send(
    phone: '+12025550123',
    idTemplate: 1,
    // Vector is generated automatically and used for encryption and request body
    // Secrets input: values is a single string; SDK will encrypt and chunk into an array
    secrets: [
        ['placeholder' => 'code', 'values' => '123456'],
    ]
);

print_r($response);
