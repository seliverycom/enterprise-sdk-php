<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Http;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\Exceptions\ApiException;

final class HttpClient
{
    private GuzzleClient $client;
    private ?string $secret;
    /** @var null|callable():(?string) */
    private $tokenProvider = null;

    public function __construct(Config $config, ?callable $tokenProvider = null, ?GuzzleClient $client = null)
    {
        $this->client = $client ?? new GuzzleClient([
            'base_uri' => rtrim($config->baseUrl, '/') . '/',
            'timeout' => $config->timeout,
        ]);
        $this->secret = $config->secret;
        $this->tokenProvider = $tokenProvider;
    }

    private function buildHeaders(array $headers = []): array
    {
        $default = [
            'Accept' => 'application/json',
        ];
        $bearer = null;
        if ($this->tokenProvider !== null) {
            try {
                $bearer = ($this->tokenProvider)();
            } catch (\Throwable) {
                // ignore and fall back to static secret
            }
        }
        if ($bearer === null || $bearer === '') {
            $bearer = $this->secret;
        }
        if (is_string($bearer) && $bearer !== '') {
            $default['Authorization'] = 'Bearer ' . $bearer;
        }
        return array_merge($default, $headers);
    }

    public function get(string $path, array|string|null $query = null, array $headers = []): array
    {
        $options = ['headers' => $this->buildHeaders($headers)];
        if (is_array($query)) {
            $options['query'] = $query;
        } elseif (is_string($query) && $query !== '') {
            $path .= (str_contains($path, '?') ? '&' : '?') . $query;
        }

        try {
            $res = $this->client->request('GET', ltrim($path, '/'), $options);
        } catch (RequestException $e) {
            $resp = $e->getResponse();
            $body = $resp ? (string) $resp->getBody() : null;
            $code = $resp ? $resp->getStatusCode() : 0;
            throw new ApiException($e->getMessage(), $code, $body);
        }

        return $this->decode((string) $res->getBody());
    }

    public function postJson(string $path, ?array $body = null, array $headers = []): array
    {
        $options = [
            'headers' => $this->buildHeaders(array_merge(['Content-Type' => 'application/json'], $headers)),
        ];
        if ($body !== null) {
            $options['json'] = $body;
        }

        try {
            $res = $this->client->request('POST', ltrim($path, '/'), $options);
        } catch (RequestException $e) {
            $resp = $e->getResponse();
            $body = $resp ? (string) $resp->getBody() : null;
            $code = $resp ? $resp->getStatusCode() : 0;
            throw new ApiException($e->getMessage(), $code, $body);
        }

        return $this->decode((string) $res->getBody());
    }

    private function decode(string $json): array
    {
        if ($json === '') {
            return [];
        }
        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }
}
