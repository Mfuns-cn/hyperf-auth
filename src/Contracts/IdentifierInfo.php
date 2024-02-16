<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Contracts;

class IdentifierInfo
{
    public function __construct(
        protected string $name,
        protected int|string $value,
    ) {}

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return int|string
     */
    public function getValue(): int|string
    {
        return $this->value;
    }

    /**
     * @param string $name
     * @return IdentifierInfo
     */
    public function setName(string $name): static
    {
        $this->name = $name;
        return $this;
    }

    /**
     * @param string $value
     * @return IdentifierInfo
     */
    public function setValue(string $value): static
    {
        $this->value = $value;
        return $this;
    }

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'value' => $this->value,
        ];
    }
}
