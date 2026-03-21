<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests;

use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\EnterpriseClient;

final class SmokeTest extends TestCase
{
    public function test_can_instantiate_client(): void
    {
        $client = new EnterpriseClient('secret');
        self::assertInstanceOf(EnterpriseClient::class, $client);
        self::assertTrue(method_exists($client, 'send'));
        self::assertTrue(method_exists($client, 'sendLight'));
    }
}
