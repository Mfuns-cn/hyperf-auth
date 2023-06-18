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

use Hyperf\Database\Model\Model;

interface AuthenticatableInterface
{
    /**
     * 获取用户的模型.
     * @param IdentifierInfo $identifierInfo
     * @return AuthenticatableInterface|Model
     */
    public function getUserModel(IdentifierInfo $identifierInfo): Model|AuthenticatableInterface;

    /**
     * 通过缓存获取用户的模型.
     * @param IdentifierInfo $identifierInfo
     * @return AuthenticatableInterface|Model
     */
    public function getUserModelFormCache(IdentifierInfo $identifierInfo): Model|AuthenticatableInterface;

    /**
     * 获取主键ID的字段名称.
     * @return string
     */
    public function getAuthIdentifierName(): string;
}
