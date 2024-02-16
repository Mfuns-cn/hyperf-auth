<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\Test\HyperfAuth\Model;

use Hyperf\Database\Model\Model;
use Mfuns\HyperfAuth\Contracts\AuthenticatableInterface;
use Mfuns\HyperfAuth\Contracts\IdentifierInfo;

class UserModel extends Model implements AuthenticatableInterface
{
    protected ?string $table = 'users';

    public function getAuthIdentifierName(): string
    {
        // TODO: Implement getAuthIdentifierName() method.
    }

    public function getUserModelFormCache(IdentifierInfo $identifierInfo): AuthenticatableInterface|Model
    {
        // TODO: Implement getUserModelFormCache() method.
    }

    public function getUserModel(IdentifierInfo $identifierInfo): AuthenticatableInterface|Model
    {
        // TODO: Implement getUserModel() method.
    }
}
