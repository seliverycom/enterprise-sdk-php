<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Service\ServiceClient;

final class ServiceEncryptionTest extends TestCase
{
    private function makeServiceClient(int $vectorLength = 32): ServiceClient
    {
        // HttpClient won't be used; we only reflectively call private methods.
        $http = new HttpClient(new Config(baseUrl: 'https://example.invalid', secret: null, timeout: 1.0));
        return new ServiceClient($http, $vectorLength);
    }

    private function generateRsaKeyPair(int $bits = 1024): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($key === false) {
            self::fail('Unable to generate RSA key');
        }
        $privPem = '';
        openssl_pkey_export($key, $privPem);
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['key'])) {
            self::fail('Unable to extract public key');
        }
        $pubPem = $details['key'];
        $pub = openssl_pkey_get_public($pubPem);
        if ($pub === false) {
            self::fail('Invalid public key');
        }
        $priv = openssl_pkey_get_private($privPem);
        if ($priv === false) {
            self::fail('Invalid private key');
        }
        return [$pub, $priv, $details];
    }

    private function callEncrypt(ServiceClient $svc, string $secret, string $vector, $publicKey): array
    {
        $rm = new \ReflectionMethod($svc, 'encrypt');
        $rm->setAccessible(true);
        /** @var array<int,string> $chunks */
        $chunks = $rm->invoke($svc, $secret, $vector, $publicKey);
        return $chunks;
    }

    public function test_encrypt_decrypt_roundtrip_single_chunk(): void
    {
        $svc = $this->makeServiceClient();
        [$pub, $priv, $details] = $this->generateRsaKeyPair(1024);
        $secret = 'hello';
        $vector = 'sms';

        $chunks = $this->callEncrypt($svc, $secret, $vector, $pub);
        self::assertCount(1, $chunks);

        $cipher = base64_decode($chunks[0], true);
        self::assertIsString($cipher);
        $plain = '';
        $ok = openssl_private_decrypt($cipher, $plain, $priv, OPENSSL_PKCS1_PADDING);
        self::assertTrue($ok);
        self::assertSame($secret . $vector, $plain);
    }

    public function test_encrypt_chunks_and_utf8_boundaries(): void
    {
        $svc = $this->makeServiceClient();
        [$pub, $priv, $details] = $this->generateRsaKeyPair(1024);

        $bits = (int) ($details['bits'] ?? 1024);
        $k = intdiv($bits + 7, 8);
        $vector = 'sms';
        $maxPlain = $k - 11 - strlen($vector);
        self::assertGreaterThan(0, $maxPlain);

        // Build secret so that an emoji would cross boundary if not rune-aware
        $secret = str_repeat('A', $maxPlain - 1) . "😀" . str_repeat('B', $maxPlain + 10);

        $chunks = $this->callEncrypt($svc, $secret, $vector, $pub);
        self::assertGreaterThanOrEqual(2, count($chunks));

        $reconstructed = '';
        foreach ($chunks as $c) {
            $cipher = base64_decode($c, true);
            self::assertIsString($cipher);
            $plain = '';
            $ok = openssl_private_decrypt($cipher, $plain, $priv, OPENSSL_PKCS1_PADDING);
            self::assertTrue($ok);
            $reconstructed .= substr($plain, 0, -strlen($vector));
        }

        self::assertSame($secret, $reconstructed);
    }

    public function test_encrypt_vector_too_long_throws(): void
    {
        $svc = $this->makeServiceClient();
        [$pub, $priv, $details] = $this->generateRsaKeyPair(1024);
        $bits = (int) ($details['bits'] ?? 1024);
        $k = intdiv($bits + 7, 8);
        $vector = str_repeat('X', $k - 10); // ensures maxPlain <= 0

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('vector too long for RSA payload');
        $this->callEncrypt($svc, 'secret', $vector, $pub);
    }
}
