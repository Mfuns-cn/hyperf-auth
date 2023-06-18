<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\Test\HyperfAuth\Cases;

use Hyperf\Utils\ApplicationContext;
use Mfuns\HyperfAuth\Contracts\AuthManagerInterface;

/**
 * @internal
 * @coversNothing
 */
class ExampleTest extends AbstractTestCase
{
    public function testExample()
    {
        //        $container = ApplicationContext::getContainer();
        //        $container->get(AuthManagerInterface::class)->guard()->
        $this->assertTrue(true);
    }
}
