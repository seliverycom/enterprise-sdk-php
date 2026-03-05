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
use Selivery\Enterprise\Config;
use Selivery\Enterprise\EnterpriseClient;

$client = new EnterpriseClient(new Config(secret: getenv('SELIVERY_SECRET') ?: ''));

/** @var Selivery\Enterprise\Models\SendResult $response */
$response = $client->service->send(
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
$response = $client->service->sendLight(
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
use Selivery\Enterprise\Config;
use Selivery\Enterprise\EnterpriseClient;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

$pool = new FilesystemAdapter(namespace: 'selivery', defaultLifetime: 0);
$psr16 = new Psr16Cache($pool);

// Options (optional):
// - cache_key: override default key (default: selivery_enterprise_sdk_tokens:{sha1(baseUrl)})
// - token_safety_window: seconds before expiry to refresh (default: 60)

$client = new EnterpriseClient(
    new Config(secret: getenv('SELIVERY_SECRET') ?: ''),
    cache: $psr16,
    options: [
        'token_safety_window' => 60,
        // 'cache_key' => 'custom_key_per_env',
    ]
);

// Service requests will reuse cached token and auto-refresh when near expiry.
```

### Service: get public keys

```php
/** @var Selivery\Enterprise\Models\PublicKeys $keys */
$keys = $client->service->getPublicKeys(['+12025550123', '+12025550124']);
```

## Examples

- Send message: `SELIVERY_SECRET=your-secret php examples/service_send.php`
- Send light message: `SELIVERY_SECRET=your-secret php examples/service_send_light.php`

## Notes

- Service API requests require `Authorization: Bearer {access_token}`.
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
