<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Tests\Unit;

use DateInterval;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

final class FakeArrayCache implements CacheInterface
{
    public bool $throwOnGet = false;
    public bool $throwOnSet = false;
    public bool $throwOnDelete = false;
    /** @var array<string,mixed> */
    private array $store = [];

    public function clear(): bool
    {
        $this->store = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = $this->get((string)$k, $default);
        }
        return $out;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if ($this->throwOnGet) {
            throw new RuntimeException('get failed');
        }
        return $this->store[$key] ?? $default;
    }

    public function setMultiple(iterable $values, int|DateInterval|null $ttl = null): bool
    {
        foreach ($values as $k => $v) {
            $this->set((string)$k, $v, $ttl);
        }
        return true;
    }

    public function set(string $key, mixed $value, int|DateInterval|null $ttl = null): bool
    {
        if ($this->throwOnSet) {
            throw new RuntimeException('set failed');
        }
        $this->store[$key] = $value;
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $k) {
            $this->delete((string)$k);
        }
        return true;
    }

    public function delete(string $key): bool
    {
        if ($this->throwOnDelete) {
            throw new RuntimeException('delete failed');
        }
        unset($this->store[$key]);
        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }
}
