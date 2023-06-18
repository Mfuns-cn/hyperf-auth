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

interface TokenProviderInterface
{
    public function __construct(array $options);

    /**
     * 加密.
     * @param HashTokenData $hashTokenData
     * @return string
     */
    public function encode(HashTokenData $hashTokenData): string;

    /**
     * 解密.
     * @param string $token
     * @return false|HashTokenData
     */
    public function decode(string $token): HashTokenData|false;
}
