<?php

namespace Hlx\Security\Fixture;

use Honeybee\Infrastructure\Fixture\Fixture;
use Honeybee\Infrastructure\Fixture\FixtureTargetInterface;

class Fixture_20160817123000_ImportAdminUser extends Fixture
{
    public function import(FixtureTargetInterface $fixture_target)
    {
        $this->copyFilesToTempLocation(__DIR__ . DIRECTORY_SEPARATOR . 'files');

        foreach ($this->getFixtureData() as $filename) {
            $this->importFixtureFromFile($filename);
        }
    }

    protected function getFixtureData()
    {
        return [
            __DIR__ . DIRECTORY_SEPARATOR . 'admin-user-data.json'
        ];
    }
}
