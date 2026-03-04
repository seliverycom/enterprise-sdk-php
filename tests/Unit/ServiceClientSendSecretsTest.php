<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Service\ServiceClient;

final class ServiceClientSendSecretsTest extends TestCase
{
    public function test_send_uses_placeholder_key_in_secrets(): void
    {
        // Generate a keypair and provide the public key as PEM in the GET response
        $key = openssl_pkey_new([
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $pubPem = $details['key'];

        $phone = '+15550001';
        $uuid = 'abc-123';
        $history = [];
        $historyMiddleware = Middleware::history($history);
        $mock = new MockHandler([
            // Response for GET /v1/clients/public-keys
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'phones' => [
                    $phone => [
                        ['uuid' => $uuid, 'publicKey' => $pubPem],
                    ],
                ],
            ], JSON_THROW_ON_ERROR)),
            // Response for POST /v1/send
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'message_uuid' => 'm-1',
                'success' => true,
            ], JSON_THROW_ON_ERROR)),
        ]);
        $stack = HandlerStack::create($mock);
        $stack->push($historyMiddleware);
        $guzzle = new GuzzleClient(['handler' => $stack, 'base_uri' => 'https://example.test/']);
        $http = new HttpClient(new Config(baseUrl: 'https://example.test', secret: 'TEST', timeout: 1.0), null, $guzzle);

        $svc = new ServiceClient($http);
        $svc->send($phone, 1, [
            ['placeholder' => 'code', 'values' => 'hello'],
        ]);

        // Inspect the POST body
        self::assertCount(2, $history);
        $post = $history[1];
        $req = $post['request'];
        $body = (string) $req->getBody();
        $data = json_decode($body, true);
        self::assertIsArray($data);
        self::assertSame($uuid, $data['key_uuid'] ?? null);
        self::assertIsArray($data['secrets'] ?? null);
        self::assertSame('code', $data['secrets'][0]['placeholder'] ?? null);
        self::assertArrayHasKey('values', $data['secrets'][0]);
        self::assertIsArray($data['secrets'][0]['values']);
        // values are base64 strings
        $val = $data['secrets'][0]['values'][0] ?? null;
        self::assertIsString($val);
        $decoded = base64_decode($val, true);
        self::assertIsString($decoded);
    }
}
