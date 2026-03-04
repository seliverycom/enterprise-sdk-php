<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Models;

final class PublicKeys
{
    /** @var array<string, array<int, PublicKey>> */
    public readonly array $phones;

    /**
     * @param array<string, array<int, PublicKey>> $phones
     */
    public function __construct(array $phones)
    {
        $this->phones = $phones;
    }

    public static function fromArray(array $data): self
    {
        $map = [];
        $phones = $data['phones'] ?? [];
        if (is_array($phones)) {
            foreach ($phones as $phone => $items) {
                $arr = [];
                if (is_array($items)) {
                    foreach ($items as $item) {
                        if (is_array($item)) {
                            $arr[] = PublicKey::fromArray($item);
                        }
                    }
                }
                $map[(string) $phone] = $arr;
            }
        }
        return new self($map);
    }

    /**
     * @return array<int, PublicKey>
     */
    public function forPhone(string $phone): array
    {
        return $this->phones[$phone] ?? [];
    }
}

