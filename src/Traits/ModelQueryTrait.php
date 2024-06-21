<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Traits;

use Hyperf\Database\Model\Builder;
use Hyperf\Database\Model\Model;
use Mfuns\HyperfAuth\Contracts\AuthenticatableInterface;

trait ModelQueryTrait
{
    protected string $model;

    public function createModel(): AuthenticatableInterface|Model
    {
        $class = '\\' . ltrim($this->model, '\\');

        return new $class();
    }

    public function getModel(): string
    {
        return $this->model;
    }

    public function setModel(string $model): static
    {
        $this->model = $model;

        return $this;
    }

    protected function newModelQuery($model = null): Builder
    {
        return is_null($model)
            ? $this->createModel()->newQuery()
            : $model->newQuery();
    }
}
