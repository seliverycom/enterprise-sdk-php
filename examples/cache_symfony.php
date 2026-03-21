<?php

declare(strict_types=1);

use Selivery\Enterprise\EnterpriseClient;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

require __DIR__ . '/../vendor/autoload.php';

// Requires: composer require symfony/cache

$pool = new FilesystemAdapter(namespace: 'selivery', defaultLifetime: 0);
$psr16 = new Psr16Cache($pool);

$client = new EnterpriseClient(
    secret: getenv('SELIVERY_SECRET') ?: '',
    cache: $psr16,
    options: [
        'token_safety_window' => 60,
        // 'cache_key' => 'custom_key',
    ]
);

// The first service call stores tokens in cache automatically.
// Subsequent service calls reuse and refresh them automatically.
// $client->send(...);
