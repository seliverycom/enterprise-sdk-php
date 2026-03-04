<?php

declare(strict_types=1);

use Selivery\Enterprise\Config;
use Selivery\Enterprise\EnterpriseClient;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

require __DIR__ . '/../vendor/autoload.php';

// Requires: composer require symfony/cache

$pool = new FilesystemAdapter(namespace: 'selivery', defaultLifetime: 0);
$psr16 = new Psr16Cache($pool);

$client = new EnterpriseClient(
    new Config(secret: getenv('SELIVERY_SECRET') ?: ''),
    cache: $psr16,
    options: [
        'token_safety_window' => 60,
        // 'cache_key' => 'custom_key',
    ]
);

// First call stores tokens in cache
$tokens = $client->auth->generateToken();
echo 'Access token: ' . $tokens->accessToken . PHP_EOL;

// Subsequent service calls reuse/refresh cached token automatically
// $client->service->send(...);
