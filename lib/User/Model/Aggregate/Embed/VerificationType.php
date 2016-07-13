<?php

namespace Hlx\Security\User\Model\Aggregate\Embed;

use Hlx\Security\User\Model\Aggregate\Embed\Base\VerificationType as BaseVerificationType;

/**
 *
 * This class reflects the declared structure of the 'Verification'
 * entity. It contains the metadata necessary to initiate and manage the
 * lifecycle of 'VerificationEntity' instances. Most importantly
 * it holds a collection of attributes (and default attributes) that each of the
 * entities of this type supports.
 *
 * For more information and hooks have a look at the base classes.
 */
class VerificationType extends BaseVerificationType
{
    //public function getDefaultAttributes()
    //{
    //    $attributes = parent::getDefaultAttributes();
    //    $attributes['language'] = new Your\Custom\LanguageAttribute('language', array('default' => 'en_UK'));
    //    $attributes['foobar'] = new Your\Custom\FooBarAttribute('foobar');
    //    return $attributes;
    //}
    //
    //protected function getEntityImplementor()
    //{
    //    return '\\Your\\Custom\\Entity';
    //}
}
