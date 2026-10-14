<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Http;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;
use Selivery\Enterprise\Auth\TokenProvider;
use Selivery\Enterprise\Config;
use Selivery\Enterprise\Exceptions\ApiException;

final class HttpClient
{
    private GuzzleClient $client;
    private ?string $secret;
    /** @var null|callable():(?string) */
    private $tokenProvider = null;

    public function __construct(
        Config $config,
        ?callable $tokenProvider = null,
        ?GuzzleClient $client = null,
        private readonly ?TokenProvider $tokenRecovery = null
    ) {
        $this->client = $client ?? new GuzzleClient([
            'base_uri' => rtrim($config->baseUrl, '/') . '/',
            'timeout' => $config->timeout,
        ]);
        $this->secret = $config->secret;
        $this->tokenProvider = $tokenProvider;
    }

    /**
     * @param array<string, string|string[]> $headers
     * @return array<string, string|string[]>
     */
    private function buildHeaders(array $headers, ?string $bearer): array
    {
        $default = [
            'Accept' => 'application/json',
        ];
        if (is_string($bearer) && $bearer !== '') {
            $default['Authorization'] = 'Bearer ' . $bearer;
        }
        // Header names are case-insensitive, including caller overrides.
        foreach ($headers as $name => $value) {
            foreach (array_keys($default) as $defaultName) {
                if (strcasecmp($name, $defaultName) === 0) {
                    unset($default[$defaultName]);
                }
            }
        }
        return array_merge($default, $headers);
    }

    /**
     * @param array<string, mixed>|string|null $query
     * @param array<string, string|string[]> $headers
     * @return array<string, mixed>
     */
    public function get(string $path, array|string|null $query = null, array $headers = []): array
    {
        $options = [];
        if (is_array($query)) {
            $options['query'] = $query;
        } elseif (is_string($query) && $query !== '') {
            $path .= (str_contains($path, '?') ? '&' : '?') . $query;
        }

        return $this->request('GET', $path, $options, $headers);
    }

    /**
     * @param array<string, mixed>|null $body
     * @param array<string, string|string[]> $headers
     * @return array<string, mixed>
     */
    public function postJson(string $path, ?array $body = null, array $headers = []): array
    {
        $options = [];
        if ($body !== null) {
            $options['json'] = $body;
        }

        return $this->request('POST', $path, $options, array_merge(['Content-Type' => 'application/json'], $headers));
    }

    /**
     * @param array<string, mixed> $options
     * @param array<string, string|string[]> $headers
     * @return array<string, mixed>
     */
    private function request(string $method, string $path, array $options, array $headers): array
    {
        $token = $this->secret;
        if ($this->tokenProvider !== null) {
            $token = ($this->tokenProvider)();
            if ($token === null || trim($token) === '') {
                throw new \RuntimeException('Token provider did not return a usable access token.');
            }
        }
        $options['headers'] = $this->buildHeaders($headers, $token);
        $options['http_errors'] = true;
        $endpoint = '/' . ltrim((string) parse_url($path, PHP_URL_PATH), '/');
        $isAuthEndpoint = in_array($endpoint, [
            '/v1/auth/generate-token',
            '/v1/auth/refresh-token',
            '/v1/auth/check-token',
        ], true);
        $managedToken = $this->tokenProvider !== null && !$isAuthEndpoint ? $token : null;
        $recovery = $this->tokenRecovery;
        foreach ($options['headers'] as $name => $value) {
            if (strcasecmp($name, 'Authorization') === 0 && $value !== 'Bearer ' . $token) {
                $managedToken = null;
            }
        }

        // Reuse the same options (including the JSON body and query) for one retry.
        for ($attempt = 0; $attempt < 2; ++$attempt) {
            try {
                $res = $this->client->request($method, ltrim($path, '/'), $options);
                return $this->decode((string) $res->getBody());
            } catch (RequestException $e) {
                $resp = $e->getResponse();
                $code = $resp ? $resp->getStatusCode() : 0;
                if ($code === 401 && $managedToken !== null && $recovery !== null) {
                    if ($attempt === 0) {
                        $managedToken = $recovery->recoverToken($managedToken);
                        foreach (array_keys($headers) as $name) {
                            if (strcasecmp($name, 'Authorization') === 0) {
                                $headers[$name] = 'Bearer ' . $managedToken;
                            }
                        }
                        $options['headers'] = $this->buildHeaders($headers, $managedToken);
                        continue;
                    }
                    $recovery->rejectToken($managedToken);
                }
                throw new ApiException(
                    $method . ' ' . $endpoint . ' failed with HTTP ' . $code,
                    $code,
                    $resp ? (string) $resp->getBody() : null,
                    $e
                );
            }
        }

        throw new \LogicException('HTTP request retry limit exceeded.');
    }

    /** @return array<string, mixed> */
    private function decode(string $json): array
    {
        if ($json === '') {
            return [];
        }
        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }
}
