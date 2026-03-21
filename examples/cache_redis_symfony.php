<?php

declare(strict_types=1);

use Selivery\Enterprise\EnterpriseClient;
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\Cache\Psr16Cache;

require __DIR__ . '/../vendor/autoload.php';

// Requires: composer require symfony/cache ext-redis

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$pool = new RedisAdapter($redis, 'selivery');
$psr16 = new Psr16Cache($pool);

$client = new EnterpriseClient(
    secret: getenv('SELIVERY_SECRET') ?: '',
    cache: $psr16
);

// Service calls generate tokens on demand and keep them in Redis cache.
// print_r($client->sendLight(...));
