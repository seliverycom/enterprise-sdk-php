<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\EnterpriseClient;
use Selivery\Enterprise\Exceptions\ApiException;

final class EnterpriseClientTokenRecoveryTest extends TestCase
{
    private array $history = [];

    private function makeClient(array $queue, bool $seedCache = true): EnterpriseClient
    {
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::history($this->history));
        $guzzle = new GuzzleClient(['handler' => $stack, 'base_uri' => 'https://example.test/']);
        $cache = new FakeArrayCache();
        if ($seedCache) {
            $cache->set('k', ['access_token' => 'OLD', 'refresh_token' => 'R1', 'expires_at' => time() + 3600]);
        }

        return new EnterpriseClient('ENTERPRISE_SECRET', $cache, [
            'base_url' => 'https://example.test', 'cache_key' => 'k', 'http_client' => $guzzle,
        ]);
    }

    private function tokenResponse(): Response
    {
        return new Response(200, [], '{"access_token":"NEW","refresh_token":"R2","session_ttl":3600}');
    }

    private function assertRequests(array $paths, array $bearers): void
    {
        self::assertCount(count($paths), $this->history);
        self::assertSame($paths, array_map(static fn (array $entry) => $entry['request']->getUri()->getPath(), $this->history));
        self::assertSame($bearers, array_map(static fn (array $entry) => $entry['request']->getHeaderLine('Authorization'), $this->history));
    }

    #[DataProvider('sendFailureStages')]
    public function testSendRecoversIndividualRequestWithoutRepeatingLookupOrEncryption(string $stage): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $keysResponse = new Response(200, [], json_encode([
            'phones' => ['15550001' => [['uuid' => 'key-1', 'publicKey' => $details['key']]]],
        ], JSON_THROW_ON_ERROR));
        $success = new Response(200, [], '{"message_uuid":"message-1","success":true}');
        $queue = $stage === 'lookup'
            ? [new Response(401), $this->tokenResponse(), $keysResponse, $success]
            : [$keysResponse, new Response(401), $this->tokenResponse(), $success];
        $client = $this->makeClient($queue);

        $result = $client->send('15550001', 1, [['placeholder' => 'code', 'values' => '123456']]);

        self::assertTrue($result->success);
        self::assertSame('message-1', $result->messageUuid);
        if ($stage === 'lookup') {
            $this->assertRequests([
                '/v1/clients/public-keys', '/v1/auth/refresh-token', '/v1/clients/public-keys', '/v1/send',
            ], ['Bearer OLD', '', 'Bearer NEW', 'Bearer NEW']);
            self::assertSame((string) $this->history[0]['request']->getUri(), (string) $this->history[2]['request']->getUri());
        } else {
            $this->assertRequests([
                '/v1/clients/public-keys', '/v1/send', '/v1/auth/refresh-token', '/v1/send',
            ], ['Bearer OLD', 'Bearer OLD', '', 'Bearer NEW']);
            self::assertSame((string) $this->history[1]['request']->getBody(), (string) $this->history[3]['request']->getBody());
        }
        $body = json_decode((string) $this->history[3]['request']->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('key-1', $body['key_uuid']);
        self::assertSame(32, strlen($body['vector']));
        self::assertSame('code', $body['secrets'][0]['placeholder']);
        $cipher = base64_decode($body['secrets'][0]['values'][0], true);
        self::assertIsString($cipher);
        $plaintext = '';
        self::assertTrue(openssl_private_decrypt($cipher, $plaintext, $key, OPENSSL_PKCS1_PADDING));
        self::assertSame('123456' . $body['vector'], $plaintext);
    }

    public static function sendFailureStages(): array
    {
        return ['GET public keys' => ['lookup'], 'POST encrypted send' => ['send']];
    }

    public function testSendLightRecoversAndReusesNewTokenOnNextCall(): void
    {
        $success = new Response(200, [], '{"message_uuid":"message-1","success":true}');
        $client = $this->makeClient([new Response(401), $this->tokenResponse(), $success, $success]);
        $secrets = [['key' => 'code', 'values' => '123456']];

        self::assertTrue($client->sendLight('15550001', 1, $secrets)->success);
        self::assertTrue($client->sendLight('15550001', 1, $secrets)->success);

        $this->assertRequests([
            '/v1/send-light', '/v1/auth/refresh-token', '/v1/send-light', '/v1/send-light',
        ], ['Bearer OLD', '', 'Bearer NEW', 'Bearer NEW']);
        self::assertSame((string) $this->history[0]['request']->getBody(), (string) $this->history[2]['request']->getBody());
        self::assertSame([
            'phone' => '15550001', 'id_template' => 1, 'secrets' => $secrets,
        ], json_decode((string) $this->history[2]['request']->getBody(), true));
    }

    #[DataProvider('sendMethods')]
    public function testEnterpriseWiringPreservesGenerationFailure(string $method): void
    {
        $client = $this->makeClient([new Response(503)], seedCache: false);

        try {
            $client->{$method}('15550001', 1);
            self::fail('Expected authentication failure before sending.');
        } catch (ApiException $e) {
            self::assertSame(503, $e->statusCode);
            self::assertStringContainsString('/v1/auth/generate-token', $e->getMessage());
        }
        $this->assertRequests(['/v1/auth/generate-token'], ['Bearer ENTERPRISE_SECRET']);
    }

    public static function sendMethods(): array
    {
        return [['send'], ['sendLight']];
    }
}
