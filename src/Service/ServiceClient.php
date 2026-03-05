<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Service;

use Selivery\Enterprise\Http\HttpClient;

final class ServiceClient
{
    public function __construct(private readonly HttpClient $http, private int $vectorLength = 32)
    {
    }

    /**
     * @param string[] $phones
     */
    public function getPublicKeys(array $phones): \Selivery\Enterprise\Models\PublicKeys
    {
        $pairs = [];
        foreach ($phones as $p) {
            $pairs[] = 'phones=' . rawurlencode($p);
        }
        $query = implode('&', $pairs);
        $data = $this->http->get('/v1/clients/public-keys', $query);
        return \Selivery\Enterprise\Models\PublicKeys::fromArray($data);
    }

    public function send(string $phone, int $idTemplate, array $secrets = []): \Selivery\Enterprise\Models\SendResult
    {
        $vector = $this->generateVector($this->vectorLength);
        $body = [
            'phone' => $phone,
            'id_template' => $idTemplate,
            'vector' => $vector,
        ];

        if ($secrets !== []) {
            // 1) Resolve public key for the phone and its UUID
            $key = $this->resolveKeyForPhone($phone);
            $keyUuid = $key['uuid'];
            $publicKey = $key['public_key'];

            // 2) Encrypt secret values using RSA PKCS#1 v1.5 and include key_uuid
            $body['key_uuid'] = $keyUuid;
            $body['secrets'] = $this->encryptSecrets($secrets, $publicKey, $vector);
        }

        $data = $this->http->postJson('/v1/send', $body);
        return \Selivery\Enterprise\Models\SendResult::fromArray($data);
    }

    public function sendLight(string $phone, int $idTemplate, array $secrets = []): \Selivery\Enterprise\Models\SendResult
    {
        $body = [
            'phone' => $phone,
            'id_template' => $idTemplate,
        ];
        if ($secrets !== []) {
            $body['secrets'] = $secrets;
        }

        $data = $this->http->postJson('/v1/send-light', $body);
        return \Selivery\Enterprise\Models\SendResult::fromArray($data);
    }

    /**
     * Accepts secrets with a single string input value and returns encrypted chunks array.
     * Vector used for encryption is generated internally using crypto-random string of configurable length.
     *
     * @param array{placeholder:string,values:string}[] $secrets Input values are plain strings
     * @return array{placeholder:string,values:array<int,string>}[] Output values are base64 chunk strings
     */
    private function encryptSecrets(array $secrets, string $publicKey, string $vector): array
    {
        $pub = $this->parsePublicKey($publicKey);
        $out = [];
        foreach ($secrets as $item) {
            $placeholder = $item['placeholder'] ?? '';
            $val = $item['values'] ?? '';
            if (!is_string($placeholder) || $placeholder === '' || !is_string($val)) {
                continue;
            }
            // Encrypt may produce multiple chunks per single input value
            $encVals = $this->encrypt($val, $vector, $pub);
            $out[] = ['placeholder' => $placeholder, 'values' => $encVals];
        }
        return $out;
    }

    /**
     * Resolve the first available key for the phone.
     * Expected API shape: { phones: { "+12025550123": [ { uuid, public_key, ... } ] } }
     * @return array{uuid:string,public_key:string}
     */
    private function resolveKeyForPhone(string $phone): array
    {
        $resp = $this->getPublicKeys([$phone]);
        $entries = $resp->forPhone($phone);
        if ($entries === []) {
            throw new \RuntimeException('No public key found for phone: ' . $phone);
        }
        $first = $entries[0];
        $uuid = $first->uuid;
        $pub = $first->publicKey;
        if ($uuid === '' || $pub === '') {
            throw new \RuntimeException('Invalid key record for phone: ' . $phone);
        }
        return ['uuid' => $uuid, 'public_key' => $pub];
    }

    /**
     * Parse an RSA public key with PKCS#1 (RSA PUBLIC KEY) first, then PEM fallbacks.
     *
     * Mirrors the Go snippet:
     * - base64 decode -> x509.ParsePKCS1PublicKey
     *
     * @return \OpenSSLAsymmetricKey|resource
     */
    private function parsePublicKey(string $publicKey)
    {
        // 1) Try base64 -> PKCS#1 (RSA PUBLIC KEY)
        $bin = base64_decode($publicKey, true);
        if ($bin !== false) {
            $pemPkcs1 = "-----BEGIN RSA PUBLIC KEY-----\n" . chunk_split(base64_encode($bin), 64, "\n") . "-----END RSA PUBLIC KEY-----\n";
            $k = @openssl_pkey_get_public($pemPkcs1);
            if ($k !== false) {
                return $k;
            }

            // Sometimes input is actually SPKI DER; try PUBLIC KEY
            $pemSpki = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($bin), 64, "\n") . "-----END PUBLIC KEY-----\n";
            $k = @openssl_pkey_get_public($pemSpki);
            if ($k !== false) {
                return $k;
            }
        }

        // 2) If it looks like PEM, try directly
        if (str_contains($publicKey, 'BEGIN')) {
            $k = @openssl_pkey_get_public($publicKey);
            if ($k !== false) {
                return $k;
            }
            $normalized = preg_replace("~\r\n?|\n~", "\n", $publicKey) ?? $publicKey;
            $k = @openssl_pkey_get_public($normalized);
            if ($k !== false) {
                return $k;
            }
        }

        // 3) Last attempt: treat original as base64 without newlines (PKCS#1 header)
        $pemFallbackPkcs1 = "-----BEGIN RSA PUBLIC KEY-----\n" . chunk_split($publicKey, 64, "\n") . "-----END RSA PUBLIC KEY-----\n";
        $k = @openssl_pkey_get_public($pemFallbackPkcs1);
        if ($k !== false) {
            return $k;
        }

        throw new \RuntimeException('Invalid RSA public key');
    }

    /**
     * Encrypt a secret string using RSA PKCS#1 v1.5, chunking like the provided Go implementation.
     * A crypto-random ASCII-hex vector of configurable length is generated per secret and
     * appended to every plaintext chunk before encryption.
     * Returns base64-encoded ciphertext chunks to embed in JSON.
     *
     * @param \OpenSSLAsymmetricKey|resource $publicKey
     * @return array<int,string> base64 strings
     */
    private function encrypt(string $secret, string $vector, $publicKey): array
    {
        $details = @openssl_pkey_get_details($publicKey);
        if (!is_array($details) || !isset($details['bits'])) {
            throw new \RuntimeException('Invalid RSA public key');
        }
        $k = (int)max(0, intdiv((int)$details['bits'] + 7, 8)); // modulus size in bytes
        $maxPlain = $k - 11 - strlen($vector);
        if ($maxPlain <= 0) {
            throw new \RuntimeException('vector too long for RSA payload');
        }

        $slen = strlen($secret);
        $pos = 0;
        $result = [];

        while ($pos < $slen) {
            $end = $pos;
            // Advance by whole UTF-8 runes without exceeding maxPlain
            while ($end < $slen) {
                $sz = $this->utf8RuneSize($secret, $end, $slen);
                if ($end + $sz - $pos > $maxPlain) {
                    break;
                }
                $end += $sz;
            }
            if ($end === $pos) {
                // Fallback: slice by bytes
                $end = min($slen, $pos + $maxPlain);
            }

            $pt = substr($secret, $pos, $end - $pos) . $vector;

            $cipher = '';
            $ok = @openssl_public_encrypt($pt, $cipher, $publicKey, OPENSSL_PKCS1_PADDING);
            if (!$ok || !is_string($cipher)) {
                throw new \RuntimeException('RSA encryption failed');
            }
            $result[] = base64_encode($cipher);
            $pos = $end;
        }

        return $result;
    }

    private function generateVector(int $length): string
    {
        if ($length <= 0) {
            return '';
        }
        $bytesLen = (int)ceil($length / 2);
        $bin = random_bytes($bytesLen);
        return substr(bin2hex($bin), 0, $length);
    }

    /**
     * Return length in bytes of next UTF-8 rune at offset, or 1 if invalid/incomplete.
     */
    private function utf8RuneSize(string $s, int $offset, int $len): int
    {
        $b = ord($s[$offset]);
        if ($b < 0x80) {
            return 1;
        }
        if ($b < 0xE0) {
            return ($offset + 1 < $len) ? 2 : 1;
        }
        if ($b < 0xF0) {
            return ($offset + 2 < $len) ? 3 : 1;
        }
        if ($b < 0xF8) {
            return ($offset + 3 < $len) ? 4 : 1;
        }
        return 1;
    }
}
