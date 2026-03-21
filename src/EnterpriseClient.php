<?php

declare(strict_types=1);

namespace Selivery\Enterprise;

use Psr\SimpleCache\CacheInterface;
use Selivery\Enterprise\Auth\AuthClient;
use Selivery\Enterprise\Auth\AuthTokenRefresher;
use Selivery\Enterprise\Auth\TokenCache;
use Selivery\Enterprise\Auth\TokenProvider;
use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Models\SendResult;
use Selivery\Enterprise\Service\ServiceClient;

final class EnterpriseClient
{
    private ServiceClient $service;

    public function __construct(string $secret, ?CacheInterface $cache = null, array $options = [])
    {
        $baseUrl = (string) ($options['base_url'] ?? 'https://enterprise-api.selivery.com');
        $timeout = (float) ($options['timeout'] ?? 10.0);
        $safetyWindow = (int) ($options['token_safety_window'] ?? 60);
        $defaultKey = 'selivery_enterprise_sdk_tokens:' . sha1($baseUrl);
        $cacheKey = (string) ($options['cache_key'] ?? $defaultKey);
        $tokenCache = new TokenCache($cache, $cacheKey, $safetyWindow);

        $generateTokenHttp = new HttpClient(new Config(baseUrl: $baseUrl, secret: $secret, timeout: $timeout));
        $authHttp = new HttpClient(new Config(baseUrl: $baseUrl, secret: null, timeout: $timeout));
        $auth = new AuthClient($generateTokenHttp, $authHttp, $tokenCache);

        $provider = new TokenProvider($tokenCache, new AuthTokenRefresher($auth), $auth);
        $httpWithAuth = new HttpClient(new Config(baseUrl: $baseUrl, secret: null, timeout: $timeout), [$provider, 'getToken']);
        $this->service = new ServiceClient($httpWithAuth);
    }

    public function send(string $phone, int $idTemplate, array $secrets = []): SendResult
    {
        return $this->service->send($phone, $idTemplate, $secrets);
    }

    public function sendLight(string $phone, int $idTemplate, array $secrets = []): SendResult
    {
        return $this->service->sendLight($phone, $idTemplate, $secrets);
    }
}
