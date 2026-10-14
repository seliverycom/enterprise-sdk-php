# Selivery Enterprise PHP SDK

Official PHP SDK for the Selivery Enterprise API.

## Installation

- Require via Composer: `composer require selivery/enterprise-sdk-php`
- Requires PHP ^8.2 with `ext-openssl` and `ext-json`.


## Usage

### Method: send

`send(...)` automatically:

- looks up the phone's public key,
- generates a crypto‑random vector (default 32 chars),
- encrypts each secret value using RSA PKCS#1 v1.5 (`openssl_public_encrypt`) with that vector, and
- includes the resolved `key_uuid` and the generated `vector` in the request.

No sender parameter is needed (it is derived from the template on the service).

```php
use Selivery\Enterprise\EnterpriseClient;

$client = new EnterpriseClient(getenv('SELIVERY_SECRET') ?: '');

/** @var Selivery\Enterprise\Models\SendResult $response */
$response = $client->send(
    phone: '+12025550123',
    idTemplate: 1,
    // Vector is generated automatically and used for encryption and request body
    secrets: [
        ['placeholder' => 'code', 'values' => '123456'],
    ]
);
```

### Method: sendLight

Difference from send:

- send encrypts values locally in the SDK and sends only encrypted chunks to Selivery. This means even Selivery (or any
  intermediary) cannot read your values.
- sendLight accepts plaintext values; Selivery encrypts them as the very first step on the server and then handles only
  encrypted values afterward. Both methods are secure; send offers an even stricter privacy boundary since plaintext
  never leaves your process.

```php
/** @var Selivery\Enterprise\Models\SendResult $response */
$response = $client->sendLight(
    phone: '+12025550123',
    idTemplate: 1,
    secrets: [
        ['key' => 'code', 'values' => '123456'],
    ]
);
```

### Token caching (PSR-16)

Inject any PSR-16 cache to enable automatic caching and refresh of OAuth tokens.

```php
use Selivery\Enterprise\EnterpriseClient;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

$pool = new FilesystemAdapter(namespace: 'selivery', defaultLifetime: 0);
$psr16 = new Psr16Cache($pool);

// Options (optional):
// - base_url: override API base URL
// - timeout: request timeout in seconds
// - cache_key: override default key (default: selivery_enterprise_sdk_tokens:{sha1(baseUrl)})
// - token_safety_window: seconds before expiry to refresh (default: 60)
// - http_client: optional Guzzle client shared by auth and service requests
//   (configure its base_uri and timeout when injecting a client)

$client = new EnterpriseClient(
    secret: getenv('SELIVERY_SECRET') ?: '',
    cache: $psr16,
    options: [
        'token_safety_window' => 60,
        // 'cache_key' => 'custom_key_per_env',
    ]
);

// The SDK generates tokens automatically on the first request,
// then reuses and refreshes them through the cache.
```

The SDK proactively refreshes tokens when `now >= expires_at - token_safety_window`.
If refresh fails or returns unusable credentials, it invalidates the stale bundle
and generates new tokens using your enterprise secret.

An access token can be revoked before its recorded expiry. When a service request
using an SDK-managed token receives HTTP 401, the SDK rejects that exact token,
refreshes it (or generates tokens if no usable refresh token is available), and
retries the original HTTP request **once**. A different valid token already stored
by another request is reused. A second 401 is propagated as `ApiException` and its
rejected token is removed from reuse. Other HTTP errors and transport failures do
not trigger this recovery, and auth endpoints are never retried by this mechanism.

Retries preserve the request body, query, and caller headers. Retrying `/v1/send`
does not repeat public-key lookup, vector generation, or encryption.

If authentication cannot produce a usable access token, the authentication failure
is propagated before a service request is sent. HTTP auth failures retain their
endpoint, status, and underlying exception; missing or empty `access_token` values
produce a descriptive validation error. Cache failures remain non-fatal: freshly
obtained tokens can still authenticate the current request. Without a working
shared cache, tokens and rejections are retained only within the client instance.
PSR-16 offers no atomic compare-and-delete, so this is not a cross-process lock;
simultaneous token rotations can still race.

## Examples

- Send message: `SELIVERY_SECRET=your-secret php examples/service_send.php`
- Send light message: `SELIVERY_SECRET=your-secret php examples/service_send_light.php`

## Notes

- `EnterpriseClient` is the only public entry point. Call `send(...)` or `sendLight(...)` on it directly.
- The SDK uses your secret only for `generate-token`.
- Service requests use the generated `access_token` automatically.
- The SDK retains tokens in the client and, if provided, the PSR-16 cache; it refreshes near expiry and recovers once after an authenticated service 401.
- POST endpoints accept JSON bodies; include `Content-Type: application/json`.
- The `sender` field has been removed from SDK methods and requests; it is derived from the template server‑side.
- Token cache key default: `selivery_enterprise_sdk_tokens:{sha1(baseUrl)}`. Avoid putting secrets in cache keys.
- Safety window default: 60s. Treats token as expired when `now >= expires_at - safety_window`.

### PSR-16 implementations

- Symfony Cache: `Psr16Cache` over `FilesystemAdapter` (disk) or `RedisAdapter` (Redis).
- Any PSR-16 provider is supported: pass your `Psr\SimpleCache\CacheInterface` to `EnterpriseClient`.

See examples:

- Symfony filesystem cache: `php examples/cache_symfony.php`
- Symfony Redis cache: `php examples/cache_redis_symfony.php`
