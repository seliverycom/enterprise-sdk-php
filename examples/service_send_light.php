<?php

declare(strict_types=1);

use Selivery\Enterprise\EnterpriseClient;

require __DIR__ . '/../vendor/autoload.php';

$secret = getenv('SELIVERY_SECRET') ?: '';
$client = new EnterpriseClient($secret);

$response = $client->sendLight(
    phone: '+12025550123',
    idTemplate: 1,
    // For send-light, values can be a string per schema and are forwarded as-is
    secrets: [
        ['key' => 'code', 'values' => '123456'],
    ]
);

print_r($response);
