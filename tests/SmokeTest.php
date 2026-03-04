<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests;

use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\EnterpriseClient;

final class SmokeTest extends TestCase
{
    public function test_can_instantiate_clients(): void
    {
        $client = new EnterpriseClient(new Config());
        self::assertNotNull($client->auth);
        self::assertNotNull($client->service);
    }
}
