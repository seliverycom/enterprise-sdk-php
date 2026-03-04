<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\Auth\TokenCache;
use Selivery\Enterprise\Auth\TokenProvider;
use Selivery\Enterprise\Auth\TokenRefresher;
use Selivery\Enterprise\Models\AuthTokens;

final class TokenProviderTest extends TestCase
{
    public function test_reuses_cached_token_when_valid(): void
    {
        $fake = new FakeArrayCache();
        $cache = new TokenCache($fake, 'k', 60);
        $cache->save(new AuthTokens('ACCESS', 'REFRESH', 300));

        $refresher = new class implements TokenRefresher {
            public function refresh(string $accessToken, string $refreshToken): AuthTokens
            {
                throw new \RuntimeException('should not refresh');
            }
        };

        $provider = new TokenProvider($cache, $refresher, null);
        self::assertSame('ACCESS', $provider->getToken());
    }

    public function test_refreshes_when_expired_and_updates_cache(): void
    {
        $fake = new FakeArrayCache();
        $cache = new TokenCache($fake, 'k', 60);
        // Force near/immediate expiry: ttl=0
        $cache->save(new AuthTokens('OLD', 'R', 0));

        $refresher = new class implements TokenRefresher {
            public function refresh(string $accessToken, string $refreshToken): AuthTokens
            {
                return new AuthTokens('NEW', 'R2', 3600);
            }
        };

        $provider = new TokenProvider($cache, $refresher, null);
        self::assertSame('NEW', $provider->getToken());
        // Cached token should now be valid and equal to NEW
        self::assertSame('NEW', $cache->getAccessTokenIfValid());
    }

    public function test_cache_exceptions_do_not_break_flow(): void
    {
        $fake = new FakeArrayCache();
        $fake->throwOnGet = true; // simulate cache get failure
        $cache = new TokenCache($fake, 'k', 60);

        $refresher = new class implements TokenRefresher {
            public function refresh(string $accessToken, string $refreshToken): AuthTokens
            {
                return new AuthTokens('NEW', 'R2', 3600);
            }
        };

        $provider = new TokenProvider($cache, $refresher, 'FALLBACK');
        self::assertSame('FALLBACK', $provider->getToken());

        // Now test set exception path: allow get, but throw on set
        $fake = new FakeArrayCache();
        $fake->set('k', [
            'access_token' => 'X',
            'refresh_token' => 'R',
            'expires_at' => time(), // expired
        ]);
        $fake->throwOnSet = true;
        $cache = new TokenCache($fake, 'k', 60);
        $provider = new TokenProvider($cache, $refresher, null);
        // Should still return NEW even if saving to cache fails
        self::assertSame('NEW', $provider->getToken());
    }
}
