<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

use Hyperf\Context\ApplicationContext;
use Mfuns\HyperfAuth\AuthManager;
use Mfuns\HyperfAuth\Contracts\GuardInterface;

if (! function_exists('auth')) {
    function auth($guard = null): GuardInterface
    {
        return ApplicationContext::getContainer()->get(AuthManager::class)->guard($guard);
    }
}
