<?php

declare(strict_types=1);

namespace Selivery\Enterprise;

use Psr\SimpleCache\CacheInterface;
use Selivery\Enterprise\Auth\AuthClient;
use Selivery\Enterprise\Auth\AuthTokenRefresher;
use Selivery\Enterprise\Auth\TokenCache;
use Selivery\Enterprise\Auth\TokenProvider;
use Selivery\Enterprise\Http\HttpClient;
use Selivery\Enterprise\Service\ServiceClient;

final class EnterpriseClient
{
    public readonly AuthClient $auth;
    public readonly ServiceClient $service;

    public function __construct(Config $config, ?CacheInterface $cache = null, array $options = [])
    {
        // Configure token cache & options
        $safetyWindow = (int) ($options['token_safety_window'] ?? 60);
        $defaultKey = 'selivery_enterprise_sdk_tokens:' . sha1($config->baseUrl);
        $cacheKey = (string) ($options['cache_key'] ?? $defaultKey);
        $tokenCache = new TokenCache($cache, $cacheKey, $safetyWindow);

        // Auth client; if your API requires Authorization on auth endpoints,
        // provide secret in Config and it will be sent.
        $authHttp = new HttpClient(new Config(baseUrl: $config->baseUrl, secret: $config->secret, timeout: $config->timeout));
        $this->auth = new AuthClient($authHttp, $tokenCache);

        // Service client with dynamic token provider
        $provider = new TokenProvider($tokenCache, new AuthTokenRefresher($this->auth), $config->secret, $this->auth);
        $httpWithAuth = new HttpClient($config, [$provider, 'getToken']);
        $this->service = new ServiceClient($httpWithAuth);
    }
}
