<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\Auth\AuthClient;
use Selivery\Enterprise\Auth\AuthTokenRefresher;
use Selivery\Enterprise\Auth\TokenCache;
use Selivery\Enterprise\Auth\TokenProvider;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\Exceptions\ApiException;
use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Models\AuthTokens;

final class HttpClientTokenRecoveryTest extends TestCase
{
    private array $history = [];
    private TokenCache $cache;
    private TokenProvider $provider;
    private GuzzleClient $guzzle;

    private function makeClient(array $queue, ?AuthTokens $tokens = null, ?FakeArrayCache $storage = null, bool $cacheEnabled = true, bool $httpErrors = true): HttpClient
    {
        $this->history = [];
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::history($this->history));
        $this->guzzle = new GuzzleClient(['handler' => $stack, 'base_uri' => 'https://example.test/', 'http_errors' => $httpErrors]);
        $this->cache = new TokenCache($cacheEnabled ? ($storage ?? new FakeArrayCache()) : null, 'k', 60);
        if ($tokens !== null) {
            $this->cache->save($tokens);
        }
        $auth = new AuthClient(
            new HttpClient(new Config(secret: 'ENTERPRISE_SECRET'), null, $this->guzzle),
            new HttpClient(new Config(), null, $this->guzzle),
            $this->cache
        );
        $this->provider = new TokenProvider($this->cache, new AuthTokenRefresher($auth), $auth);

        return new HttpClient(new Config(), [$this->provider, 'getToken'], $this->guzzle, $this->provider);
    }

    private function tokenResponse(string $access = 'NEW', string $refresh = 'R2'): Response
    {
        return new Response(200, [], json_encode([
            'access_token' => $access,
            'refresh_token' => $refresh,
            'session_ttl' => 3600,
        ], JSON_THROW_ON_ERROR));
    }

    private function assertRequests(array $paths, array $bearers): void
    {
        self::assertCount(count($paths), $this->history);
        self::assertSame($paths, array_map(static fn (array $entry) => $entry['request']->getUri()->getPath(), $this->history));
        self::assertSame($bearers, array_map(static fn (array $entry) => $entry['request']->getHeaderLine('Authorization'), $this->history));
    }

    public function testValidCachedTokenDoesNotCallAuth(): void
    {
        $http = $this->makeClient([new Response(200, [], '{"phones":{}}')], new AuthTokens('OLD', 'R1', 3600));

        self::assertSame(['phones' => []], $http->get('/v1/clients/public-keys'));
        $this->assertRequests(['/v1/clients/public-keys'], ['Bearer OLD']);
    }

    public function testEmptyCacheGeneratesBeforeServiceRequest(): void
    {
        $http = $this->makeClient([$this->tokenResponse(), new Response(200)]);

        $http->get('/v1/clients/public-keys');
        $this->assertRequests(['/v1/auth/generate-token', '/v1/clients/public-keys'], ['Bearer ENTERPRISE_SECRET', 'Bearer NEW']);
        self::assertSame('POST', $this->history[0]['request']->getMethod());
    }

    #[DataProvider('proactiveTtls')]
    public function testExpiredOrNearlyExpiredTokenRefreshesProactively(int $ttl): void
    {
        $http = $this->makeClient([$this->tokenResponse(), new Response(200)], new AuthTokens('OLD', 'R1', $ttl));

        $http->get('/v1/clients/public-keys');
        $this->assertRequests(['/v1/auth/refresh-token', '/v1/clients/public-keys'], ['', 'Bearer NEW']);
        self::assertSame([
            'access_token' => 'OLD', 'refresh_token' => 'R1', 'regenerate_refresh' => false,
        ], json_decode((string) $this->history[0]['request']->getBody(), true));
    }

    public static function proactiveTtls(): array
    {
        return ['expired' => [0], 'inside safety window' => [30]];
    }

    public function testRejectedProactiveRefreshFallsBackToGeneration(): void
    {
        $http = $this->makeClient([new Response(401), $this->tokenResponse(), new Response(200)], new AuthTokens('OLD', 'R1', 0));

        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/auth/refresh-token', '/v1/auth/generate-token', '/v1/clients/public-keys',
        ], ['', 'Bearer ENTERPRISE_SECRET', 'Bearer NEW']);
    }

    #[DataProvider('getQueries')]
    public function testRejectedUnexpiredTokenRefreshesAndSubsequentCallsReuseNewToken(array|string $query): void
    {
        $http = $this->makeClient([
            new Response(401), $this->tokenResponse(), new Response(200, [], '{"ok":true}'), new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600));

        self::assertSame(['ok' => true], $http->get('/v1/clients/public-keys', $query, ['X-Caller' => 'original']));
        $http->get('/v1/clients/public-keys', $query);

        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys', '/v1/clients/public-keys',
        ], ['Bearer OLD', '', 'Bearer NEW', 'Bearer NEW']);
        self::assertSame((string) $this->history[0]['request']->getUri(), (string) $this->history[2]['request']->getUri());
        self::assertSame('original', $this->history[2]['request']->getHeaderLine('X-Caller'));
        self::assertSame('NEW', $this->cache->getAccessTokenIfValid());
    }

    public static function getQueries(): array
    {
        return ['repeated query parameters' => ['phones=15550001&phones=15550002'], 'array query' => [['phone' => '15550001']]];
    }

    public function testPostRecoveryPreservesBodyQueryAndCallerHeaders(): void
    {
        $http = $this->makeClient([new Response(401), $this->tokenResponse(), new Response(200)], new AuthTokens('OLD', 'R1', 3600));
        $body = [
            'phone' => '15550001', 'id_template' => 1, 'key_uuid' => 'key-1', 'vector' => 'original-vector',
            'secrets' => [['placeholder' => 'code', 'values' => ['encrypted-value']]],
        ];

        $http->postJson('/v1/send?mode=original', $body, ['X-Caller' => ['first', 'second'], 'content-type' => 'application/json; charset=utf-8']);

        $this->assertRequests(['/v1/send', '/v1/auth/refresh-token', '/v1/send'], ['Bearer OLD', '', 'Bearer NEW']);
        $first = $this->history[0]['request'];
        $retry = $this->history[2]['request'];
        self::assertSame('POST', $retry->getMethod());
        self::assertSame((string) $first->getUri(), (string) $retry->getUri());
        self::assertSame((string) $first->getBody(), (string) $retry->getBody());
        self::assertSame($body, json_decode((string) $retry->getBody(), true));
        $expectedHeaders = $first->getHeaders();
        $expectedHeaders['Authorization'] = ['Bearer NEW'];
        self::assertSame($expectedHeaders, $retry->getHeaders());
    }

    #[DataProvider('unusableRefreshTokens')]
    public function test401WithoutUsableRefreshGeneratesAndRetries(string $refresh): void
    {
        $http = $this->makeClient([new Response(401), $this->tokenResponse(), new Response(200)], new AuthTokens('OLD', $refresh, 3600));

        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/generate-token', '/v1/clients/public-keys',
        ], ['Bearer OLD', 'Bearer ENTERPRISE_SECRET', 'Bearer NEW']);
    }

    public static function unusableRefreshTokens(): array
    {
        return ['empty' => [''], 'whitespace' => ['   ']];
    }

    #[DataProvider('refreshFailures')]
    public function testRecoveryRefreshFailureFallsBackToGeneration(Response $failure): void
    {
        $http = $this->makeClient([new Response(401), $failure, $this->tokenResponse(), new Response(200)], new AuthTokens('OLD', 'R1', 3600));

        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/auth/generate-token', '/v1/clients/public-keys',
        ], ['Bearer OLD', '', 'Bearer ENTERPRISE_SECRET', 'Bearer NEW']);
    }

    public static function refreshFailures(): array
    {
        return [
            'rejected' => [new Response(401)], 'unavailable' => [new Response(503)],
            'missing access token' => [new Response(200, [], '{"refresh_token":"R2"}')],
            'same rejected access token' => [new Response(200, [], '{"access_token":"OLD","refresh_token":"R2","session_ttl":3600}')],
        ];
    }

    #[DataProvider('requestMethods')]
    public function testSecond401StopsAndRejectedTokensAreNotReused(string $method): void
    {
        $storage = new FakeArrayCache();
        $http = $this->makeClient([
            new Response(401), $this->tokenResponse(), new Response(401, [], '{"error":"Invalid auth token"}'),
            $this->tokenResponse('NEXT'), new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600), $storage);

        try {
            $this->serviceRequest($http, $method);
            self::fail('Expected the second service 401 to propagate.');
        } catch (ApiException $e) {
            self::assertSame(401, $e->statusCode);
            self::assertSame('{"error":"Invalid auth token"}', $e->responseBody);
            self::assertInstanceOf(RequestException::class, $e->getPrevious());
        }
        self::assertCount(3, $this->history);
        self::assertNull($this->cache->getAccessTokenIfValid());
        self::assertNull($storage->get('k'));

        $this->serviceRequest($http, $method);
        $this->assertRequests([
            '/v1/send', '/v1/auth/refresh-token', '/v1/send', '/v1/auth/generate-token', '/v1/send',
        ], ['Bearer OLD', '', 'Bearer NEW', 'Bearer ENTERPRISE_SECRET', 'Bearer NEXT']);
    }

    public function testGenerationFailurePropagatesWithoutServiceRequest(): void
    {
        $http = $this->makeClient([new Response(503, [], '{"error":"Auth unavailable"}')]);

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected authentication failure.');
        } catch (ApiException $e) {
            self::assertSame(503, $e->statusCode);
            self::assertStringContainsString('/v1/auth/generate-token', $e->getMessage());
            self::assertInstanceOf(RequestException::class, $e->getPrevious());
        }
        $this->assertRequests(['/v1/auth/generate-token'], ['Bearer ENTERPRISE_SECRET']);
    }

    #[DataProvider('generationFailureStatuses')]
    public function testRecoveryAuthFailuresDoNotRecursivelyRetry(int $status): void
    {
        $http = $this->makeClient([new Response(401), new Response(401), new Response($status)], new AuthTokens('OLD', 'R1', 3600));

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected generation failure.');
        } catch (ApiException $e) {
            self::assertSame($status, $e->statusCode);
            self::assertStringContainsString('/v1/auth/generate-token', $e->getMessage());
        }
        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/auth/generate-token',
        ], ['Bearer OLD', '', 'Bearer ENTERPRISE_SECRET']);
        self::assertNull($this->cache->getAccessTokenIfValid());
    }

    public static function generationFailureStatuses(): array
    {
        return [[401], [503]];
    }

    #[DataProvider('authEndpoints')]
    public function testAuthEndpointsNeverUseServiceRecoveryEvenIfWired(string $path): void
    {
        $http = $this->makeClient([new Response(401)], new AuthTokens('OLD', 'R1', 3600));

        try {
            $http->postJson($path);
            self::fail('Expected auth endpoint failure.');
        } catch (ApiException $e) {
            self::assertSame(401, $e->statusCode);
        }
        $this->assertRequests([$path], ['Bearer OLD']);
        self::assertSame('OLD', $this->cache->getAccessTokenIfValid());
    }

    public static function authEndpoints(): array
    {
        return [['/v1/auth/generate-token'], ['/v1/auth/refresh-token'], ['/v1/auth/check-token']];
    }

    #[DataProvider('invalidAccessTokens')]
    public function testInvalidGenerationResponseFailsBeforeServiceRequest(array $payload): void
    {
        $payload['refresh_token'] = 'PRIVATE_REFRESH_TOKEN';
        $http = $this->makeClient([new Response(200, [], json_encode($payload, JSON_THROW_ON_ERROR))]);

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected invalid access_token to fail.');
        } catch (ApiException $e) {
            self::assertStringContainsString('/v1/auth/generate-token', $e->getMessage());
            self::assertStringContainsString('non-empty access_token string', $e->getMessage());
            self::assertStringNotContainsString('PRIVATE_REFRESH_TOKEN', $e->getMessage());
            self::assertNull($e->responseBody);
            self::assertInstanceOf(\InvalidArgumentException::class, $e->getPrevious());
        }
        $this->assertRequests(['/v1/auth/generate-token'], ['Bearer ENTERPRISE_SECRET']);
        self::assertNull($this->cache->get());
    }

    public static function invalidAccessTokens(): array
    {
        return ['missing' => [[]], 'empty' => [['access_token' => '']], 'whitespace' => [['access_token' => '  ']],
            'null' => [['access_token' => null]], 'wrong type' => [['access_token' => ['invalid']]]];
    }

    #[DataProvider('non401Responses')]
    public function testOtherHttpFailuresDoNotRecover(string $method, int $status): void
    {
        $http = $this->makeClient([new Response($status)], new AuthTokens('OLD', 'R1', 3600));

        try {
            $this->serviceRequest($http, $method);
            self::fail('Expected HTTP error.');
        } catch (ApiException $e) {
            self::assertSame($status, $e->statusCode);
        }
        $this->assertRequests(['/v1/send'], ['Bearer OLD']);
        self::assertSame('OLD', $this->cache->getAccessTokenIfValid());
    }

    public static function non401Responses(): iterable
    {
        foreach (['GET', 'POST'] as $method) {
            foreach ([400, 403, 404, 429, 500, 503] as $status) {
                yield $method . ' ' . $status => [$method, $status];
            }
        }
    }

    #[DataProvider('requestMethods')]
    public function testTransportFailuresDoNotRecover(string $method): void
    {
        $failure = new ConnectException('Connection failed', new Request($method, 'https://example.test/v1/send'));
        $http = $this->makeClient([$failure], new AuthTokens('OLD', 'R1', 3600));

        try {
            $this->serviceRequest($http, $method);
            self::fail('Expected transport error.');
        } catch (ConnectException $e) {
            self::assertSame($failure, $e);
        }
        $this->assertRequests(['/v1/send'], ['Bearer OLD']);
    }

    public static function requestMethods(): array
    {
        return [['GET'], ['POST']];
    }

    private function serviceRequest(HttpClient $http, string $method): void
    {
        if ($method === 'GET') {
            $http->get('/v1/send');
        } else {
            $http->postJson('/v1/send', ['phone' => '15550001']);
        }
    }

    #[DataProvider('cacheFailures')]
    public function testCacheFailuresStillAuthenticateWithFreshTokens(string $operation): void
    {
        $storage = new FakeArrayCache();
        $http = $this->makeClient([$this->tokenResponse(), new Response(200)], storage: $storage);
        $storage->throwOnGet = $operation === 'get' || $operation === 'all';
        $storage->throwOnSet = $operation === 'set' || $operation === 'all';
        $storage->throwOnDelete = $operation === 'all';

        $http->get('/v1/clients/public-keys');
        $this->assertRequests(['/v1/auth/generate-token', '/v1/clients/public-keys'], ['Bearer ENTERPRISE_SECRET', 'Bearer NEW']);
    }

    public static function cacheFailures(): array
    {
        return [['get'], ['set'], ['all']];
    }

    public function testFailedCacheDeletionAndWriteCannotResurrectRejectedTokens(): void
    {
        $storage = new FakeArrayCache();
        $http = $this->makeClient([
            new Response(401), $this->tokenResponse(), new Response(401), $this->tokenResponse('NEXT'), new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600), $storage);
        $storage->throwOnDelete = true;
        $storage->throwOnSet = true;

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected second service 401.');
        } catch (ApiException $e) {
            self::assertSame(401, $e->statusCode);
        }
        self::assertNull($this->cache->getAccessTokenIfValid());
        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys',
            '/v1/auth/generate-token', '/v1/clients/public-keys',
        ], ['Bearer OLD', '', 'Bearer NEW', 'Bearer ENTERPRISE_SECRET', 'Bearer NEXT']);
    }

    public function testRecoveryUsesLocalRefreshCredentialsWithoutSharedCache(): void
    {
        $http = $this->makeClient([
            $this->tokenResponse('OLD', 'R1'), new Response(401), $this->tokenResponse(), new Response(200),
        ], cacheEnabled: false);

        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/auth/generate-token', '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys',
        ], ['Bearer ENTERPRISE_SECRET', 'Bearer OLD', '', 'Bearer NEW']);
    }

    public function testNewerCachedTokenIsPreservedWhenOldRequestIsRejected(): void
    {
        $storage = new FakeArrayCache();
        $http = $this->makeClient([
            static function () use ($storage): Response {
                $storage->set('k', ['access_token' => 'NEWER', 'refresh_token' => 'R2', 'expires_at' => time() + 3600]);
                return new Response(401);
            },
            new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600), $storage);

        $http->get('/v1/clients/public-keys');
        $this->assertRequests(['/v1/clients/public-keys', '/v1/clients/public-keys'], ['Bearer OLD', 'Bearer NEWER']);
        self::assertSame('NEWER', $this->cache->getAccessTokenIfValid());
    }

    public function testSecondRejectionAlsoPreservesNewerCachedToken(): void
    {
        $storage = new FakeArrayCache();
        $http = $this->makeClient([
            new Response(401), $this->tokenResponse(),
            static function () use ($storage): Response {
                $storage->set('k', ['access_token' => 'NEWER', 'refresh_token' => 'R3', 'expires_at' => time() + 3600]);
                return new Response(401);
            },
        ], new AuthTokens('OLD', 'R1', 3600), $storage);

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected second service 401.');
        } catch (ApiException $e) {
            self::assertSame(401, $e->statusCode);
        }
        self::assertCount(3, $this->history);
        self::assertSame('NEWER', $this->cache->getAccessTokenIfValid());
    }

    public function testNewerTokenStoredDuringFailedRefreshIsReusedWithoutGeneration(): void
    {
        $storage = new FakeArrayCache();
        $http = $this->makeClient([
            new Response(401),
            static function () use ($storage): Response {
                $storage->set('k', ['access_token' => 'NEWER', 'refresh_token' => 'R2', 'expires_at' => time() + 3600]);
                return new Response(401);
            },
            new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600), $storage);

        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys',
        ], ['Bearer OLD', '', 'Bearer NEWER']);
        self::assertSame('NEWER', $this->cache->getAccessTokenIfValid());
    }

    public function testInjectedGuzzleDefaultsCannotDisable401Recovery(): void
    {
        $http = $this->makeClient([
            new Response(401), $this->tokenResponse(), new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600), httpErrors: false);

        $http->get('/v1/clients/public-keys');
        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys',
        ], ['Bearer OLD', '', 'Bearer NEW']);
    }

    public function testCallerAuthorizationDoesNotRejectManagedToken(): void
    {
        $http = $this->makeClient([new Response(401)], new AuthTokens('OLD', 'R1', 3600));

        try {
            $http->get('/v1/clients/public-keys', headers: ['authorization' => 'Bearer CALLER_TOKEN']);
            self::fail('Expected caller token rejection.');
        } catch (ApiException $e) {
            self::assertSame(401, $e->statusCode);
        }
        $this->assertRequests(['/v1/clients/public-keys'], ['Bearer CALLER_TOKEN']);
        self::assertSame('OLD', $this->cache->getAccessTokenIfValid());
    }

    #[DataProvider('authorizationHeaderNames')]
    public function testExplicitManagedAuthorizationUsesRecoveredTokenOnRetry(string $headerName): void
    {
        $http = $this->makeClient([
            new Response(401), $this->tokenResponse(), new Response(200),
        ], new AuthTokens('OLD', 'R1', 3600));

        $http->get('/v1/clients/public-keys', headers: [$headerName => 'Bearer OLD', 'X-Caller' => 'original']);

        $this->assertRequests([
            '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys',
        ], ['Bearer OLD', '', 'Bearer NEW']);
        self::assertSame('original', $this->history[2]['request']->getHeaderLine('X-Caller'));
        self::assertSame('NEW', $this->cache->getAccessTokenIfValid());
    }

    public static function authorizationHeaderNames(): array
    {
        return [['Authorization'], ['authorization']];
    }

    public function testStaticSecret401DoesNotRecover(): void
    {
        $this->makeClient([new Response(401)]);
        $http = new HttpClient(new Config(secret: 'ENTERPRISE_SECRET'), null, $this->guzzle, $this->provider);

        try {
            $http->postJson('/v1/auth/generate-token');
            self::fail('Expected secret rejection.');
        } catch (ApiException $e) {
            self::assertSame(401, $e->statusCode);
        }
        $this->assertRequests(['/v1/auth/generate-token'], ['Bearer ENTERPRISE_SECRET']);
    }

    public function testProviderFailureIsNotSwallowedOrReplacedByStaticSecret(): void
    {
        $this->makeClient([]);
        $failure = new \RuntimeException('Token acquisition failed');
        $http = new HttpClient(new Config(secret: 'ENTERPRISE_SECRET'), static function () use ($failure): ?string {
            throw $failure;
        }, $this->guzzle);

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected provider failure.');
        } catch (\RuntimeException $e) {
            self::assertSame($failure, $e);
        }
        self::assertCount(0, $this->history);
    }

    #[DataProvider('emptyProviderTokens')]
    public function testEmptyProviderTokenPreventsServiceRequest(?string $token): void
    {
        $this->makeClient([]);
        $http = new HttpClient(new Config(secret: 'ENTERPRISE_SECRET'), static fn () => $token, $this->guzzle);

        try {
            $http->get('/v1/clients/public-keys');
            self::fail('Expected unusable token failure.');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('usable access token', $e->getMessage());
        }
        self::assertCount(0, $this->history);
    }

    public static function emptyProviderTokens(): array
    {
        return [[null], [''], ['   ']];
    }
}
