<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\Auth\AuthClient;
use Selivery\Enterprise\Auth\TokenCache;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\Http\HttpClient;

final class AuthClientCacheTest extends TestCase
{
    public function test_tokens_written_after_generate_token(): void
    {
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'AAA',
                'refresh_token' => 'RRR',
                'session_ttl' => 1800,
            ], JSON_THROW_ON_ERROR)),
        ]);
        $client = new GuzzleClient(['handler' => HandlerStack::create($mock), 'base_uri' => 'https://example.test/']);
        $generateTokenHttp = new HttpClient(new Config(baseUrl: 'https://example.test', secret: 'SECRET', timeout: 1.0), null, $client);
        $authHttp = new HttpClient(new Config(baseUrl: 'https://example.test', secret: null, timeout: 1.0), null, $client);

        $fake = new FakeArrayCache();
        $cache = new TokenCache($fake, 'k', 60);

        $auth = new AuthClient($generateTokenHttp, $authHttp, $cache);
        $tokens = $auth->generateToken();

        self::assertSame('AAA', $tokens->accessToken);
        $bundle = $cache->get();
        self::assertIsArray($bundle);
        self::assertSame('AAA', $bundle['access_token']);
        self::assertSame('RRR', $bundle['refresh_token']);
        self::assertGreaterThan(time(), $bundle['expires_at']);
    }
}
